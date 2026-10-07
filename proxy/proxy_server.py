"""
gRPC server that receives telemetry from Cisco WLCs.

Implements the bidirectional streaming MdtDialout RPC:
1. Receive telemetry from WLC
2. AP filter check (drop out-of-scope messages before hashing)
3. Hash MACs
4. Forward to InnerSpace
5. Return ACK to WLC
"""
import asyncio
import logging
import grpc
import time
from google.protobuf.message import DecodeError

from proto import mdt_dialout_pb2
from proto import mdt_dialout_pb2_grpc
from proto import telemetry_bis_pb2

from .mac_hasher import MACHasher, UnsupportedTelemetryEncoding
from .grpc_forwarder import GRPCForwarder
from .ap_filter import APFilter
from .config import ProxyConfig

logger = logging.getLogger(__name__)


class ProxyMDTDialoutServicer(mdt_dialout_pb2_grpc.gRPCMdtDialoutServicer):
    """Receives Cisco MDT messages, hashes MACs, and forwards to InnerSpace."""

    def __init__(self, hasher: MACHasher, forwarder: GRPCForwarder, ap_filter: APFilter = None):
        self.hasher = hasher
        self.forwarder = forwarder
        self.ap_filter = ap_filter
        logger.info("ProxyMDTDialoutServicer initialized")
    
    async def MdtDialout(self, request_iterator, context):
        """
        Handle bidirectional streaming RPC from WLC.
        
        Flow for each message:
        1. Receive MdtDialoutArgs from WLC
        2. Parse telemetry protobuf
        3. AP filter check (drop out-of-scope messages before hashing)
        4. Hash all MACs
        5. Forward to InnerSpace
        6. Yield ACK back to WLC
        
        Args:
            request_iterator: Stream of MdtDialoutArgs from WLC
            context: gRPC context
        
        Yields:
            MdtDialoutArgs with ACK (ReqId)
        """
        peer = context.peer()
        logger.info(f"New WLC stream connected from {peer}")
        
        try:
            async for request in request_iterator:
                t_start = time.perf_counter()
                
                try:
                    telemetry = telemetry_bis_pb2.Telemetry()
                    try:
                        telemetry.ParseFromString(request.data)
                    except DecodeError as e:
                        logger.error(f"Failed to parse telemetry protobuf: {e}")
                        # Still ACK to prevent WLC from blocking
                        yield mdt_dialout_pb2.MdtDialoutArgs(ReqId=request.ReqId)
                        continue
                    
                    node_id = telemetry.node_id_str if telemetry.HasField('node_id_str') else 'unknown'
                    encoding_path = telemetry.encoding_path if telemetry.encoding_path else 'unknown'

                    logger.debug(f"Processing message ReqId={request.ReqId}, node={node_id}, path={encoding_path}")

                    # Runs before hashing so a dropped message skips that work.
                    if self.ap_filter and not self.ap_filter.should_forward(telemetry):
                        logger.info(
                            f"Filtered out message (no in-scope APs): "
                            f"ReqId={request.ReqId}, path={encoding_path}"
                        )
                        yield mdt_dialout_pb2.MdtDialoutArgs(ReqId=request.ReqId)
                        continue

                    t_hash_start = time.perf_counter()
                    try:
                        macs_hashed = self.hasher.hash_message(telemetry)
                    except UnsupportedTelemetryEncoding as e:
                        logger.error(
                            f"Unsupported telemetry encoding for ReqId={request.ReqId}: {e}"
                        )
                        yield mdt_dialout_pb2.MdtDialoutArgs(ReqId=request.ReqId)
                        continue
                    t_hash_end = time.perf_counter()
                    hash_duration_ms = (t_hash_end - t_hash_start) * 1000

                    logger.debug(f"Hashed {macs_hashed} MACs in {hash_duration_ms:.2f}ms")
                    
                    hashed_data = telemetry.SerializeToString()

                    try:
                        ack_req_id = await asyncio.wait_for(
                            self.forwarder.forward(request.ReqId, hashed_data),
                            timeout=30.0  # 30 seconds timeout for forward operation
                        )
                    except asyncio.TimeoutError:
                        logger.error(f"Timeout forwarding message ReqId={request.ReqId} to InnerSpace (30s)")
                        ack_req_id = None

                    if ack_req_id is None:
                        logger.warning(f"Failed to forward message ReqId={request.ReqId}")
                    
                    # ACK even after forwarding failures to avoid controller backpressure.
                    yield mdt_dialout_pb2.MdtDialoutArgs(ReqId=request.ReqId)
                    
                    t_end = time.perf_counter()
                    total_duration_ms = (t_end - t_start) * 1000
                    
                    logger.debug(f"Message ReqId={request.ReqId} processed in {total_duration_ms:.2f}ms")
                    
                except Exception as e:
                    logger.exception(f"Error processing message ReqId={request.ReqId}: {e}")
                    
                    yield mdt_dialout_pb2.MdtDialoutArgs(ReqId=request.ReqId)
        
        finally:
            logger.info(f"WLC stream disconnected from {peer}")


async def start_grpc_server(
    servicer: ProxyMDTDialoutServicer,
    host: str,
    port: int,
    config: ProxyConfig
) -> grpc.aio.Server:
    """
    Start the gRPC server with proper configuration.

    Args:
        servicer: ProxyMDTDialoutServicer instance
        host: Host to bind to
        port: Port to bind to
        config: Proxy configuration (for server options)

    Returns:
        Started gRPC server
    """
    options = [
        ('grpc.max_concurrent_streams', config.max_concurrent_streams),
        ('grpc.keepalive_time_ms', 30000),  # Send keepalive ping every 30 seconds
        ('grpc.keepalive_timeout_ms', 10000),  # Wait 10 seconds for keepalive response
        ('grpc.keepalive_permit_without_calls', 1),  # Allow keepalive pings when no calls
        ('grpc.max_receive_message_length', 20 * 1024 * 1024),
        ('grpc.max_send_message_length', 20 * 1024 * 1024),
    ]

    server = grpc.aio.server(options=options)
    mdt_dialout_pb2_grpc.add_gRPCMdtDialoutServicer_to_server(servicer, server)
    
    if config.proxy_use_tls:
        with open(config.proxy_tls_cert, 'rb') as f:
            cert = f.read()
        with open(config.proxy_tls_key, 'rb') as f:
            key = f.read()
        credentials = grpc.ssl_server_credentials([(key, cert)])
        server.add_secure_port(f"{host}:{port}", credentials)
        logger.info(f"TLS enabled (cert: {config.proxy_tls_cert})")
    else:
        server.add_insecure_port(f"{host}:{port}")

    await server.start()

    logger.info(f"gRPC server started on {host}:{port} (TLS: {config.proxy_use_tls})")
    logger.info("Ready to receive telemetry from Cisco WLCs")
    
    return server

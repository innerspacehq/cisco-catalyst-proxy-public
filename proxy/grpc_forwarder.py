"""
gRPC client forwarder to InnerSpace.

Forwards hashed telemetry messages to InnerSpace using the same
gRPC protocol that Cisco WLCs use.
"""
import asyncio
import logging
import grpc
import time
from typing import Optional

from proto import mdt_dialout_pb2
from proto import mdt_dialout_pb2_grpc

logger = logging.getLogger(__name__)


class GRPCForwarder:
    """
    Forward hashed telemetry to InnerSpace via gRPC.

    Failed forwards are reported to logs and dropped. The WLC side still gets
    an ACK so telemetry does not back up on the controller.
    """
    
    def __init__(self, endpoint: str, use_tls: bool = False):
        self.endpoint = endpoint
        self.use_tls = use_tls
        self.channel: Optional[grpc.aio.Channel] = None
        self.stub = None
        self._connected = False
        self._connect_lock = asyncio.Lock()
        self._last_connect_attempt = 0.0  # Timestamp of last connection attempt
        self._connect_cooldown = 1.0  # Minimum seconds between connection attempts
        logger.info(f"GRPCForwarder initialized for endpoint: {endpoint} (TLS: {use_tls})")
    
    async def connect(self):
        """Establish gRPC channel to InnerSpace."""
        async with self._connect_lock:
            if self._connected and self.stub:
                return

            self._last_connect_attempt = time.time()
            channel = None

            try:
                logger.info(f"Connecting to InnerSpace at {self.endpoint}...")

                if self.use_tls:
                    # Production path: validate against the system default trust
                    # store for InnerSpace's publicly trusted certificate.
                    credentials = grpc.ssl_channel_credentials()
                    channel = grpc.aio.secure_channel(self.endpoint, credentials)
                else:
                    channel = grpc.aio.insecure_channel(self.endpoint)

                stub = mdt_dialout_pb2_grpc.gRPCMdtDialoutStub(channel)

                await asyncio.wait_for(channel.channel_ready(), timeout=10.0)
                old_channel = self.channel
                self.channel = channel
                self.stub = stub
                self._connected = True

                if old_channel and old_channel is not channel:
                    await old_channel.close()

                logger.info(f"Connected to InnerSpace at {self.endpoint}")

            except asyncio.TimeoutError:
                logger.error(f"Timeout connecting to InnerSpace at {self.endpoint} (10s)")
                self._connected = False
                if channel:
                    await channel.close()
                self.channel = None
                self.stub = None
                raise
            except Exception as e:
                logger.error(f"Failed to connect to InnerSpace: {e}")
                self._connected = False
                if channel:
                    await channel.close()
                self.channel = None
                self.stub = None
                raise
    
    async def forward(self, req_id: int, data: bytes) -> Optional[int]:
        """
        Forward a single message to InnerSpace.

        Args:
            req_id: Request ID from WLC
            data: Serialized telemetry data (with hashed MACs)

        Returns:
            ACK ReqId from InnerSpace, or None if failed
        """
        if not self._connected or not self.stub:
            time_since_last_attempt = time.time() - self._last_connect_attempt
            if time_since_last_attempt < self._connect_cooldown:
                logger.debug(f"Skipping reconnect (cooldown: {time_since_last_attempt:.1f}s < {self._connect_cooldown}s)")
                return None

            logger.warning("Not connected to InnerSpace, attempting to connect...")
            try:
                await self.connect()
            except Exception as e:
                logger.error(f"Failed to connect: {e}")
                return None
        
        try:
            t_start = time.perf_counter()
            request = mdt_dialout_pb2.MdtDialoutArgs(
                ReqId=req_id,
                data=data
            )
            
            async def request_iterator():
                yield request
            
            async for ack in self.stub.MdtDialout(request_iterator()):
                t_end = time.perf_counter()
                duration_ms = (t_end - t_start) * 1000
                
                logger.debug(f"Forwarded message ReqId={req_id}, ACK received in {duration_ms:.2f}ms")
                return ack.ReqId
            
            # If we get here, no ACK received
            logger.warning(f"No ACK received for ReqId={req_id}")
            return None
            
        except grpc.aio.AioRpcError as e:
            logger.error(f"gRPC error forwarding message: {e.code()} - {e.details()}")
            self._connected = False
            # Clean up failed connection
            if self.channel:
                await self.channel.close()
            self.channel = None
            self.stub = None
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error forwarding message: {e}")
            return None
    
    async def close(self):
        """Close the gRPC channel."""
        if self.channel:
            logger.info("Closing InnerSpace connection...")
            await self.channel.close()
            self._connected = False
            logger.info("InnerSpace connection closed")
    
    def is_connected(self) -> bool:
        """Check if connected to InnerSpace."""
        return self._connected

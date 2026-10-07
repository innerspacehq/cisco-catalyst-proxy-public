"""
Main entry point for the Cisco Catalyst MAC Hashing Proxy.

Partial MAC hashing:
- OUI (first 3 bytes): Preserved in plaintext (lowercase)
- NIC (last 3 bytes): Hashed with HMAC-SHA256
"""
import argparse
import asyncio
import logging
import signal
import sys

from proxy.config import ProxyConfig, setup_logging
from proxy.mac_hasher import MACHasher
from proxy.grpc_forwarder import GRPCForwarder
from proxy.ap_filter import APFilter
from proxy.proxy_server import ProxyMDTDialoutServicer, start_grpc_server

logger = logging.getLogger(__name__)

AP_FILTER_SUMMARY_INTERVAL_SECONDS = 300


async def _log_ap_filter_summary_periodically(ap_filter: APFilter):
    while True:
        await asyncio.sleep(AP_FILTER_SUMMARY_INTERVAL_SECONDS)
        ap_filter.log_summary()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Cisco Catalyst MAC Hashing Proxy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'examples:\n'
            '  python proxy_main.py --config configs/production.yml\n'
            '\n'
            'required environment variables (set via shell or .env):\n'
            '  HMAC_SECRET           hex-encoded secret, min 64 chars (32 bytes)\n'
            '                        generate: openssl rand -hex 32\n'
            '  INNERSPACE_ENDPOINT   host:port of the InnerSpace gRPC server\n'
        ),
    )
    parser.add_argument(
        '--config',
        required=True,
        metavar='CONFIG_FILE',
        help='Path to a self-contained YAML config file',
    )
    return parser.parse_args()


async def main():
    """Main entry point for the proxy."""
    args = parse_args()

    try:
        config = ProxyConfig.from_yaml(args.config)
        setup_logging(config.log_level)
    except (ValueError, FileNotFoundError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Cisco Catalyst MAC Hashing Proxy")
    logger.info("=" * 60)

    logger.info("Initializing proxy components...")

    secret = config.get_hmac_secret_bytes()
    hasher = MACHasher(secret)

    forwarder = GRPCForwarder(
        config.innerspace_endpoint,
        use_tls=config.innerspace_use_tls,
    )
    try:
        await forwarder.connect()
    except Exception as e:
        logger.error(f"Failed to connect to InnerSpace: {e}")
        logger.error("Proxy will still start, but messages may be dropped until connection is established")

    ap_filter = APFilter(
        enabled=config.ap_filtering.enabled,
        allow_list=config.ap_filtering.allow_list,
    ) if config.ap_filtering.enabled else None

    summary_task = asyncio.create_task(_log_ap_filter_summary_periodically(ap_filter)) if ap_filter else None

    servicer = ProxyMDTDialoutServicer(hasher, forwarder, ap_filter)
    grpc_server = await start_grpc_server(
        servicer,
        config.proxy_host,
        config.proxy_port,
        config,
    )

    logger.info("=" * 60)
    logger.info("Proxy initialization complete")
    logger.info(f"WLC endpoint:  {config.proxy_host}:{config.proxy_port} (TLS: {config.proxy_use_tls})")
    logger.info(f"InnerSpace:    {config.innerspace_endpoint} (TLS: {config.innerspace_use_tls})")
    logger.info("=" * 60)

    # Setup signal handlers for graceful shutdown.
    #
    # loop.add_signal_handler() (not signal.signal()) is required here: a
    # raw signal.signal() handler can interrupt the event loop mid-operation,
    # and its wakeup of a waiting coroutine (via Event.set()) isn't reliably
    # picked up by the loop; it can be delayed indefinitely until something
    # else happens to wake it. add_signal_handler() runs the callback safely
    # through the loop's own scheduling instead.
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def signal_handler():
        logger.info("Received shutdown signal, shutting down...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    # Wait for shutdown signal
    await stop_event.wait()

    # Graceful shutdown
    logger.info("Shutting down proxy...")

    if summary_task:
        summary_task.cancel()
    if ap_filter:
        ap_filter.log_summary()

    logger.info("Stopping gRPC server...")
    await grpc_server.stop(grace=5)

    logger.info("Closing InnerSpace connection...")
    await forwarder.close()

    logger.info("Proxy shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)

"""Configuration management for the MAC hashing proxy."""
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
_MAC_REGEX = re.compile(r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$')


@dataclass
class APFilteringConfig:
    """AP filtering configuration (ANY logic)."""
    enabled: bool = True
    allow_list: list = field(default_factory=list)

    def validate(self):
        """Raise ValueError if enabled with no allowlist, or any MAC is malformed."""
        if self.enabled and not self.allow_list:
            raise ValueError(
                "ap_filtering.enabled is true but allow_list is empty — every "
                "message would be dropped. Set allow_list, or set enabled: false."
            )
        for mac in self.allow_list:
            if not _MAC_REGEX.match(mac):
                raise ValueError(
                    f"Invalid MAC address in ap_filtering.allow_list: {mac}"
                )


@dataclass
class ProxyConfig:
    """Configuration for the MAC hashing proxy."""
    hmac_secret: str
    proxy_host: str
    proxy_port: int
    max_concurrent_streams: int
    proxy_use_tls: bool
    proxy_tls_cert: str
    proxy_tls_key: str
    innerspace_endpoint: str
    innerspace_use_tls: bool
    log_level: str
    ap_filtering: APFilteringConfig = field(default_factory=APFilteringConfig)

    @classmethod
    def from_yaml(cls, config_file: str) -> "ProxyConfig":
        """Load YAML settings and required deployment values from environment."""
        path = Path(config_file)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        raw = yaml.safe_load(path.read_text()) or {}

        proxy_cfg = raw.get('proxy', {})
        innerspace_cfg = raw.get('innerspace', {})
        app_cfg = raw.get('app', {})
        ap_filtering_cfg = raw.get('ap_filtering', {})

        hmac_secret = os.environ.get('HMAC_SECRET', '')
        if not hmac_secret:
            raise ValueError("HMAC_SECRET environment variable is required")

        innerspace_endpoint = os.environ.get('INNERSPACE_ENDPOINT', '')
        if not innerspace_endpoint:
            raise ValueError("INNERSPACE_ENDPOINT environment variable is required")

        try:
            proxy_port = int(proxy_cfg.get('port', 57000))
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"proxy.port must be an integer, got: {proxy_cfg.get('port')!r}"
            ) from e

        try:
            max_streams = int(proxy_cfg.get('max_concurrent_streams', 10))
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"proxy.max_concurrent_streams must be an integer, "
                f"got: {proxy_cfg.get('max_concurrent_streams')!r}"
            ) from e

        log_level = os.environ.get('LOG_LEVEL', app_cfg.get('log_level', 'INFO')).upper()
        if log_level not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"app.log_level must be one of {sorted(_VALID_LOG_LEVELS)}, "
                f"got: {log_level!r}"
            )

        try:
            secret_bytes = bytes.fromhex(hmac_secret)
        except ValueError as e:
            raise ValueError(
                "HMAC_SECRET must be a valid hex string"
            ) from e
        if len(secret_bytes) < 32:
            raise ValueError(
                f"HMAC_SECRET must be at least 64 hex characters "
                f"(32 bytes) for 256-bit security; got {len(secret_bytes)} bytes. "
                f"Generate one with: openssl rand -hex 32"
            )

        ap_filtering = APFilteringConfig(
            enabled=bool(ap_filtering_cfg.get('enabled', True)),
            allow_list=ap_filtering_cfg.get('allow_list', []) or [],
        )
        ap_filtering.validate()

        config = cls(
            hmac_secret=hmac_secret,
            proxy_host=proxy_cfg.get('host', '[::]'),
            proxy_port=proxy_port,
            max_concurrent_streams=max_streams,
            proxy_use_tls=bool(proxy_cfg.get('use_tls', False)),
            proxy_tls_cert=proxy_cfg.get('tls_cert', './ssl/server.cert'),
            proxy_tls_key=proxy_cfg.get('tls_key', './ssl/server.key'),
            innerspace_endpoint=innerspace_endpoint,
            innerspace_use_tls=bool(innerspace_cfg.get('use_tls', True)),
            log_level=log_level,
            ap_filtering=ap_filtering,
        )

        if config.proxy_use_tls:
            for path, label in [
                (config.proxy_tls_cert, 'proxy.tls_cert'),
                (config.proxy_tls_key, 'proxy.tls_key'),
            ]:
                if not Path(path).exists():
                    raise FileNotFoundError(
                        f"TLS file not found ({label}): {path}. "
                        f"Provide a certificate/key pair from your PKI."
                    )

        logger.info("Configuration loaded:")
        logger.info(
            f"  Proxy:      {config.proxy_host}:{config.proxy_port} "
            f"(TLS: {config.proxy_use_tls})"
        )
        logger.info(
            f"  InnerSpace: {config.innerspace_endpoint} "
            f"(TLS: {config.innerspace_use_tls})"
        )
        if config.ap_filtering.enabled:
            logger.info(
                f"  AP filtering: ENABLED ({len(config.ap_filtering.allow_list)} allowed APs)"
            )
        else:
            logger.info("  AP filtering: DISABLED")
        return config

    def get_hmac_secret_bytes(self) -> bytes:
        """Return the already-validated HMAC secret as bytes."""
        return bytes.fromhex(self.hmac_secret)


def setup_logging(log_level: str = "INFO"):
    """Configure logging for the proxy."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.getLogger("grpc").setLevel(logging.WARNING)

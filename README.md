# Cisco Catalyst MAC Hashing Proxy

Reference container for receiving Cisco Catalyst/WLC model-driven telemetry,
hashing MAC addresses inside the telemetry payload, and forwarding the modified
gRPC stream to InnerSpace ingest.

The proxy is intended to run inside the customer network. For supported Cisco
GPBKV telemetry subscriptions, raw MAC addresses are processed locally. The
proxy forwards MAC-derived identifiers where the OUI is preserved and the
device-specific portion is replaced with an HMAC-SHA256 value.

## Data Flow

```text
Cisco WLC/Catalyst 9800 -> Proxy container -> InnerSpace ingest
        raw MACs              hashed MACs        hashed MACs
```

For each telemetry message, the proxy:

1. Receives Cisco MDT dial-out gRPC messages.
2. Parses the Cisco telemetry protobuf payload.
3. Checks the message's access point against the configured allow list; out-of-scope messages are dropped here, before hashing.
4. Replaces MAC addresses found in telemetry string and UTF-8 byte fields.
5. Forwards the modified message to the configured InnerSpace endpoint.
6. ACKs the Cisco stream.

## AP Filtering

The proxy can restrict forwarding to a configured list of access point (AP) MAC
addresses. A message is forwarded only if it contains at least one AP MAC in
the allow list; otherwise it is dropped before hashing.

AP filtering is on by default and requires a non-empty allow list, or the
proxy refuses to start:

```yaml
ap_filtering:
  enabled: true
  allow_list:
    - "aa:bb:cc:dd:ee:ff"
```

To disable AP filtering, set `enabled: false`.

## Privacy Model

MAC addresses matching colon, hyphen, Cisco dotted, or compact hex notation are
transformed with HMAC-SHA256:

```text
Input:  AA:BB:CC:DD:EE:FF
Output: aa:bb:cc:<64-character-hmac-sha256>
```

The first three bytes, the OUI, remain visible for vendor-level analytics. The
last three bytes are hashed with the customer-provided `HMAC_SECRET`.

`HMAC_SECRET` is the deployment's stable HMAC key. Generate it once, store it in
a production secret manager, and reuse the same value on every proxy restart.
InnerSpace analytics depend on the same device producing the same hashed
identifier over time. Changing `HMAC_SECRET` changes all generated identifiers
and breaks continuity with previously ingested data.

## Configuration

Required environment variables:

```text
HMAC_SECRET          Stable hex-encoded secret, at least 64 characters.
INNERSPACE_ENDPOINT  InnerSpace gRPC endpoint as host:port.
```

Optional:

```text
LOG_LEVEL            DEBUG, INFO, WARNING, ERROR, or CRITICAL. Default: INFO.
```

`configs/production.yml` contains service settings such as listener port and
TLS mode. Secrets and the InnerSpace endpoint are supplied through environment
variables, not YAML.

Generate `HMAC_SECRET` once and store it in your normal secret manager:

```bash
openssl rand -hex 32
```

## Run With Podman

```bash
podman build -t cisco-catalyst-proxy .

export HMAC_SECRET="<stable-secret-from-your-secret-manager>"
export INNERSPACE_ENDPOINT="<innerspace-host>:<innerspace-port>"

podman run --rm --name cisco-catalyst-proxy \
  -p 57000:57000 \
  -e HMAC_SECRET="$HMAC_SECRET" \
  -e INNERSPACE_ENDPOINT="$INNERSPACE_ENDPOINT" \
  cisco-catalyst-proxy
```

## Run With Docker

```bash
docker build -t cisco-catalyst-proxy .

export HMAC_SECRET="<stable-secret-from-your-secret-manager>"
export INNERSPACE_ENDPOINT="<innerspace-host>:<innerspace-port>"

docker run --rm --name cisco-catalyst-proxy \
  -p 57000:57000 \
  -e HMAC_SECRET="$HMAC_SECRET" \
  -e INNERSPACE_ENDPOINT="$INNERSPACE_ENDPOINT" \
  cisco-catalyst-proxy
```

The container defaults to `configs/production.yml`.

## Running As A Service

The `podman run` and `docker run` commands above are convenient for testing. For
a production deployment, run the proxy as a managed service so it restarts on
failure and comes back after a host reboot. Compose is the recommended path for a
single-host deployment; rootless Podman with systemd (Quadlet) adds
boot-persistence under a dedicated service account on RHEL 9.

### Build And Host The Image

This repository ships a Dockerfile, not a prebuilt image. Build it from the
Dockerfile and host it in a container registry your deployment hosts can reach:

```bash
podman build -t your-registry.example.com/cisco-catalyst-proxy:1.0.0 .
podman push your-registry.example.com/cisco-catalyst-proxy:1.0.0
```

The examples below reference that image tag. On a single build host, Compose can
instead build the image locally from the Dockerfile (the `build:` key below), so
no registry is required for that case.

### Environment File

Both paths read the same two secrets from an environment file rather than the
shell. Create `proxy.env` (mode `0600`), mirroring `.env.example`:

```text
HMAC_SECRET=<stable-secret-from-your-secret-manager>
INNERSPACE_ENDPOINT=<innerspace-host>:<innerspace-port>
# LOG_LEVEL=INFO
```

### Compose

A ready-to-edit `compose.yaml` ships in the repository root. It works with both
`podman compose` and `docker compose`. Note that `podman compose` delegates to a
separate provider (`podman-compose` or Docker's compose plugin); a minimal RHEL 9
host has neither installed by default, so install one first. `docker compose`
needs no extra provider.

```yaml
# Example Compose file for the Cisco Catalyst MAC Hashing Proxy.
# Create proxy.env (see the README "Running As A Service" section) before starting.
# Works with both `podman compose` and `docker compose`.
services:
  cisco-catalyst-proxy:
    image: cisco-catalyst-proxy
    build: .
    container_name: cisco-catalyst-proxy
    restart: unless-stopped
    ports:
      - "57000:57000"
    env_file:
      - proxy.env
    # Optional WLC-facing TLS: supply a TLS config and mount the certs. On
    # SELinux hosts (RHEL) :Z relabels the mounts. Under rootless Podman the
    # container runs as a non-root user, so the files must be readable by it:
    # podman compose accepts an extra ,U (e.g. :ro,Z,U) to remap ownership;
    # docker compose does not, so grant read access another way.
    # command: ["--config", "configs/production-tls.yml"]
    # volumes:
    #   - ./certs:/certs:ro,Z
    #   - ./production-tls.yml:/app/configs/production-tls.yml:ro,Z
```

```bash
podman compose up -d      # or: docker compose up -d
podman compose logs -f    # expect "Ready to receive telemetry from Cisco WLCs"
podman compose down
```

Compose does not start the workload at boot on its own. For an unattended host
that must survive reboots, use the systemd approach below.

### Rootless Podman + systemd On RHEL 9

This reference uses rootless Podman with a Quadlet unit under a dedicated service
account. Validated on a CIS Level 1 (Server) hardened RHEL 9 host with Podman
5.x; Quadlet requires Podman 4.4+. Run the numbered steps as an administrator
(`sudo`).

```bash
# 1. Dedicated rootless service user. enable-linger starts this user's systemd
#    manager at boot, which is what makes the service auto-start.
sudo useradd --create-home --shell /bin/bash svc-catalyst-proxy
sudo loginctl enable-linger svc-catalyst-proxy

# 2. Persist the user-bus location for the service account's login shells.
#    Without this, `sudo -iu ... systemctl --user` cannot reach the user's
#    systemd manager ("Failed to connect to bus"). Use the service user's home
#    path explicitly: a leading ~ would expand to the calling admin's home.
sudo -iu svc-catalyst-proxy tee -a /home/svc-catalyst-proxy/.bash_profile >/dev/null <<'EOF'
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
EOF

# 3. Secrets file, owned by and readable only by the service user.
sudo -iu svc-catalyst-proxy install -d -m 700 /home/svc-catalyst-proxy/.config/cisco-catalyst-proxy
sudo -iu svc-catalyst-proxy tee /home/svc-catalyst-proxy/.config/cisco-catalyst-proxy/proxy.env >/dev/null <<'EOF'
HMAC_SECRET=<stable-secret-from-your-secret-manager>
INNERSPACE_ENDPOINT=<innerspace-host>:<innerspace-port>
EOF
sudo -iu svc-catalyst-proxy chmod 600 /home/svc-catalyst-proxy/.config/cisco-catalyst-proxy/proxy.env

# 4. Pull the image you built and pushed to your registry (see "Build And Host
#    The Image" above) into the service user's local storage. Authenticate first
#    if the registry is private: sudo -iu svc-catalyst-proxy podman login <registry>.
sudo -iu svc-catalyst-proxy podman pull your-registry.example.com/cisco-catalyst-proxy:1.0.0

# 5. Install the Quadlet unit (contents below).
sudo -iu svc-catalyst-proxy install -d /home/svc-catalyst-proxy/.config/containers/systemd
```

Write this to
`/home/svc-catalyst-proxy/.config/containers/systemd/cisco-catalyst-proxy.container`:

```ini
[Unit]
Description=Cisco Catalyst MAC Hashing Proxy

[Container]
ContainerName=cisco-catalyst-proxy
Image=your-registry.example.com/cisco-catalyst-proxy:1.0.0
# Run the copy already pulled in step 4; do not re-fetch on every start.
Pull=missing
PublishPort=57000:57000
EnvironmentFile=%h/.config/cisco-catalyst-proxy/proxy.env
# Optional WLC-facing TLS. The container runs as a non-root user, so each mount
# needs both Z (SELinux relabel) and U (map the mount's ownership to the
# container user). Without U, a cert/key/config created under a umask 027 (CIS)
# host is mode 0640 and the proxy exits with "Permission denied".
# Volume=%h/.config/cisco-catalyst-proxy/certs:/certs:ro,Z,U
# Volume=%h/.config/cisco-catalyst-proxy/production-tls.yml:/app/configs/production-tls.yml:ro,Z,U
# Exec=--config configs/production-tls.yml

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
# 6. Load the unit and start the service. Quadlet generates
#    cisco-catalyst-proxy.service from the .container file. Do not hand-write
#    a .service unit.
sudo -iu svc-catalyst-proxy systemctl --user daemon-reload
sudo -iu svc-catalyst-proxy systemctl --user start cisco-catalyst-proxy.service

# 7. Open the WLC-facing port. Rootless Podman cannot bind ports below 1024;
#    57000 is fine.
sudo firewall-cmd --permanent --add-port=57000/tcp
sudo firewall-cmd --reload
```

Verify and operate:

```bash
sudo -iu svc-catalyst-proxy systemctl --user status cisco-catalyst-proxy.service
sudo -iu svc-catalyst-proxy podman logs -f cisco-catalyst-proxy
ss -tlnp | grep 57000
sudo -iu svc-catalyst-proxy systemctl --user restart cisco-catalyst-proxy.service
```

Notes:

- Because the listener speaks gRPC (HTTP/2), verify it with the port check and
  the `Ready to receive telemetry from Cisco WLCs` log line rather than a plain
  HTTP `curl`.
- `enable-linger` plus `WantedBy=default.target` is what auto-starts the service
  at boot; a separate `systemctl --user enable` is not required.
- Keep everything under the service user. Rootless Podman refuses a `~/.config`
  it does not own, so always operate through `sudo -iu svc-catalyst-proxy`.
- Rootless Podman needs subuid/subgid ranges for the service user. `useradd`
  allocates them by default on RHEL 9; confirm with
  `grep svc-catalyst-proxy /etc/subuid /etc/subgid`.
- The Quadlet keys map to the earlier `podman run` flags: `PublishPort` is `-p`,
  `EnvironmentFile` replaces the `-e` variables, and `Restart=on-failure`
  replaces `--restart`.

## Telemetry Encoding

Configure Cisco MDT subscriptions to use self-describing GPBKV encoding. This
reference proxy does not decode compact GPB payloads because that requires
per-path protobuf schemas. If compact GPB rows are received, the proxy ACKs the
Cisco stream but does not forward that message to InnerSpace.

## Sample Telemetry Data

The [samples/cisco-telemetry](samples/cisco-telemetry) directory contains a
schema reference and synthetic sample messages for the Cisco Catalyst WLC
wireless telemetry subscriptions used by this integration.

## TLS And Network Controls

Outbound TLS to InnerSpace is enabled in the production config. InnerSpace
ingest uses a publicly trusted certificate, so no custom CA file is needed.

Use WLC-facing TLS in production unless an approved compensating network control
strictly limits access to the proxy listener. If the Cisco WLC is configured
with a trustpoint for the proxy endpoint, the proxy must present a server
certificate that the WLC trustpoint trusts. The customer is responsible for
providing this proxy server certificate and private key.

Restrict access to the WLC-facing listener with firewall rules, security groups,
ACLs, or equivalent controls so only approved Cisco WLC/Catalyst telemetry
sources can connect to port 57000.

Non-TLS is the default and the path used for testing: the shipped
`configs/production.yml` sets `proxy.use_tls: false`, so no WLC-facing
certificate is used and no `/certs` mount is required.

To enable WLC-facing TLS, create your own config file (this repository does not
ship one; the examples call it `production-tls.yml`) that sets:

```yaml
proxy:
  use_tls: true
  tls_cert: "/certs/server.cert"
  tls_key: "/certs/server.key"
```

Then mount that config plus the proxy server certificate and private key into
the container. Under rootless Podman the container runs as a non-root user, so
each mount uses `Z` (SELinux relabel) and `U` (map the mount's ownership to the
container user) rather than a bare `:ro`:

```bash
podman run --rm --name cisco-catalyst-proxy \
  -p 57000:57000 \
  -v ./certs:/certs:ro,Z,U \
  -v ./production-tls.yml:/app/configs/production-tls.yml:ro,Z,U \
  -e HMAC_SECRET="$HMAC_SECRET" \
  -e INNERSPACE_ENDPOINT="$INNERSPACE_ENDPOINT" \
  cisco-catalyst-proxy --config configs/production-tls.yml
```

## Operational Behavior

The proxy ACKs Cisco messages after local processing even if forwarding to
InnerSpace fails. This prevents WLC backpressure, but messages can be dropped
during InnerSpace outages or network failures. Monitor container logs in
production deployments.

Run the container with the narrowest runtime privileges supported by your
platform, for example a read-only filesystem, no added Linux capabilities, and
`no-new-privileges`.

Do not rotate `HMAC_SECRET` as routine maintenance. Coordinate with InnerSpace
before changing it.

## Testing

Install development dependencies:

```bash
python3 -m venv venv
. venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The public test suite verifies MAC detection, deterministic hashing, OUI
preservation, secret-dependent output, and AP allow-list matching.

Before end-to-end testing, update `configs/production.yml`'s
`ap_filtering.allow_list` with your deployment's actual AP MACs. AP filtering
is on by default, so a test stream will be dropped entirely if the shipped
example MACs are still in place. End-to-end validation should be done by
pointing a Cisco MDT dial-out test stream at the proxy and confirming
InnerSpace receives hashed identifiers.

## Repository Status

This repository is a public reference snapshot exported from InnerSpace's
internal development repository. Changes are published here as reviewed
snapshots.

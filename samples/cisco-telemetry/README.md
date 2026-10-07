# Cisco Catalyst WLC Wireless Telemetry (Schema and Samples)

These files describe the wireless operational telemetry your Cisco Catalyst 9800 /
IOS-XE wireless LAN controller (WLC) streams via **Model-Driven Telemetry (MDT)
dial-out over gRPC**, for the subscriptions used in this integration. They are
provided so you can review the exact structure and content of the data your
controller sends to the configured telemetry receiver.

## Files

| File | What it is |
|---|---|
| `cisco-wlc-telemetry-schema.json` | **Schema reference.** For each telemetry subscription: the Cisco YANG module, the `encodingPath`, the key field(s), the value types, and one worked example message. |
| `cisco-wlc-telemetry-sample-data.json` | **Illustrative sample dataset.** A small example deployment (a few APs, clients, and rogues) rendered as realistic messages in the same format. This is **synthetic** (not captured from a live WLC), with values randomized within plausible ranges and MACs built from real vendor prefixes. |
| `cisco-wlc-telemetry-proxy-output-sample.json` | **Proxy output examples.** One synthetic message per documented subscription after MAC hashing, showing the shape forwarded from the proxy to InnerSpace. It uses a public demo HMAC secret so the output is reproducible; production output depends on the deployment's `HMAC_SECRET`. |

Field names, paths, and types come from the standard Cisco IOS-XE 17.14 wireless
operational YANG models (`Cisco-IOS-XE-wireless-{client,rrm,rogue,location}-oper`).

## How the data is shaped

Each telemetry message is a self-describing key-value structure (GPB-KV). On the
wire, the WLC sends binary protobuf messages over gRPC, and the proxy forwards
binary protobuf messages after hashing MAC addresses. The JSON files in this
directory are decoded, human-readable renderings of those protobuf messages; the
WLC does not send JSON to the proxy, and the proxy does not send JSON to
InnerSpace.

A message has an **envelope** plus a payload:

```jsonc
{
  "nodeIdStr": "wlc-001",                       // which WLC is reporting
  "subscriptionIdStr": "15075",                 // the telemetry subscription id
  "encodingPath": "Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats",
  "collectionId": "76",
  "msgTimestamp": "1751994143000",              // epoch milliseconds (as a string)
  "dataGpbkv": [                                 // one or more rows
    {
      "timestamp": "1751994143000",
      "fields": [
        { "name": "keys",    "fields": [ /* the identifier(s) for this row */ ] },
        { "name": "content", "fields": [ /* the reported values           */ ] }
      ]
    }
  ]
}
```

- **`encodingPath`** identifies which data set the message carries (a standard
  Cisco YANG operational path, configured as a subscription on the WLC).
- **`fields`** is a list; each field has a `name` and either a typed value or a
  nested `fields` array (for grouped/list data).
- **`keys`** holds the identifier(s) for the row (e.g. a client or AP MAC address);
  **`content`** holds the reported values.

### Value types

| Key in JSON | Meaning |
|---|---|
| `stringValue` | text, MAC address, timestamp, IP address, or enumeration name |
| `uint32Value` | unsigned integer (channel, slot, counts, levels) |
| `uint64Value` | large counters (bytes/packets); may appear as a string per protobuf JSON conventions |
| `sint32Value` | signed integer: RSSI (negative dBm) and most SNR leaves (dB) |
| `boolValue` | true/false flag |
| nested `fields` | a field with child `fields` (instead of a value) is a container or list |

## Subscriptions covered

| Subscription | encodingPath | Reports |
|---|---|---|
| Per-client statistics | `...client-oper:client-oper-data/traffic-stats` | Per client: traffic counters and most-recent RSSI/SNR |
| AP RRM RF neighbors | `...rrm-oper:rrm-oper-data/ap-auto-rf-dot11-data` | Per AP radio: neighboring radios detected and their signal metrics |
| Rogue clients | `...rogue-oper:rogue-oper-data/rogue-client-data` | Rogue/unclassified clients detected, with detecting radio and signal |
| Rogue access points | `...rogue-oper:rogue-oper-data/rogue-data` | Rogue/unknown APs detected, classification, strongest detecting radio |
| Location RSSI measurements | `...location-oper:location-oper-data/location-rssi-measurements` | Per-client RSSI sample measurements, keyed by client and detecting radio |

## Notes

- Each example shows a **representative subset** of fields; a live WLC may include
  additional leaves from the same YANG container.
- Timestamps are epoch milliseconds sent as strings. RSSI is a signed integer
  (negative dBm); SNR is signed on most leaves, though some (e.g. `most-recent-snr`)
  are emitted as `uint32Value`.
- The sample dataset is **synthetic and illustrative**: safe to share and inspect,
  but it does not represent any real devices.
- The proxy-output sample preserves the first three MAC bytes (OUI) and replaces
  the remaining device-specific bytes with a 64-character HMAC-SHA256 digest.

# Third-Party Notices

This repository includes protobuf schemas and generated Python protobuf bindings
derived from Cisco model-driven telemetry definitions.

## Cisco Systems, Inc.

Files:

- `proto/telemetry_bis.proto`
- `proto/telemetry_bis_pb2.py`
- `proto/telemetry_bis_pb2_grpc.py`
- `proto/mdt_dialout_pb2.py`
- `proto/mdt_dialout_pb2_grpc.py`

Notice:

```text
Copyright (c) 2016 by Cisco Systems, Inc.
Copyright (c) 2020 Cisco Systems, Inc. and/or its affiliates.
```

License: Apache License, Version 2.0. See `LICENSE-APACHE-2.0.txt`.

Modification notice: the Python protobuf bindings in this repository were
generated from the Cisco protobuf schema files with the local protobuf/gRPC
toolchain used by InnerSpace for this reference proxy. Header comments from
`.proto` files are not preserved by `protoc`, so this notice preserves the
required Cisco attribution for the generated files.

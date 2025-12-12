## peer-observer protobuf types

These protobuf definitions are used for the communication between an extractor
and tools. They define events that the extractors publish and the tools consume.

The top-level event is the `Event` defined in `protobuf/event.proto`.

### Rust types (fully support)

The Rust types and implementations for these protobuf definitions are generated
in `shared/build.rs`. See `shared/src/protobuf/` for the implementions of these
types.

### Python types (somewhat supported)

Python types can be generated with the following code snippet. While Python
tools are supported in theory, in partice these are harder to test with the
current cargo testing infrastructure. So they are ommited from this repository
for now.

```bash
SRC_DIR="./protobuf"
DST_DIR="python-types"

mkdir -p $DST_DIR

protoc -I=$SRC_DIR --python_out=$DST_DIR $SRC_DIR/*.proto
```

A sample Python tool that logs P2P messages looks like this:

```python
# needs these python packages
# - nats-py
# - protobuf

import asyncio
from nats.aio.client import Client as NATS
import json
import sys
sys.path.append("../../python-types")

import event_msg_pb2

async def main():
    nc = NATS()

    await nc.connect("nats://127.0.0.1:4222")

    async def message_handler(msg):
        subject = msg.subject
        data = msg.data

        event = event_msg_pb2.Event()
        event.ParseFromString(data)

        p2pmsg = event.msg
        print(f"{"inbound" if p2pmsg.meta.inbound else "outbound"} {p2pmsg.meta.command}")

    await nc.subscribe("netmsg", cb=message_handler)
    print("Subscribed to 'netmsg' topic...")

    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

```

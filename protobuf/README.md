## peer-observer protobuf types

These protobuf definitions are used for the communication between an extractor
and tools. They define events that the extractors publish and the tools consume.

The top-level event is the `Event` defined in `protobuf/event.proto`.

### Rust types

The Rust types and implementations for these protobuf definitions are generated
in `shared/build.rs`. See `shared/src/protobuf/` for the implementions of these
types.

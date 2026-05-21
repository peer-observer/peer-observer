use shared::async_nats;
use shared::async_nats::ConnectErrorKind;
use shared::prost::DecodeError;
use std::error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum RuntimeError {
    ProtobufDecode(DecodeError),
    NatsSubscribe(async_nats::client::SubscribeError),
    NatsConnect(shared::async_nats::error::Error<ConnectErrorKind>),
    Io(io::Error),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RuntimeError::ProtobufDecode(e) => write!(f, "protobuf decode error {}", e),
            RuntimeError::NatsSubscribe(e) => write!(f, "NATS subscribe error {}", e),
            RuntimeError::NatsConnect(e) => write!(f, "NATS connection error {}", e),
            RuntimeError::Io(e) => write!(f, "IO error {}", e),
        }
    }
}

impl error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            RuntimeError::ProtobufDecode(ref e) => Some(e),
            RuntimeError::NatsSubscribe(ref e) => Some(e),
            RuntimeError::NatsConnect(ref e) => Some(e),
            RuntimeError::Io(ref e) => Some(e),
        }
    }
}

impl From<DecodeError> for RuntimeError {
    fn from(e: DecodeError) -> Self {
        RuntimeError::ProtobufDecode(e)
    }
}

impl From<async_nats::client::SubscribeError> for RuntimeError {
    fn from(e: async_nats::client::SubscribeError) -> Self {
        RuntimeError::NatsSubscribe(e)
    }
}

impl From<shared::async_nats::error::Error<ConnectErrorKind>> for RuntimeError {
    fn from(e: shared::async_nats::error::Error<ConnectErrorKind>) -> Self {
        RuntimeError::NatsConnect(e)
    }
}

impl From<io::Error> for RuntimeError {
    fn from(e: io::Error) -> Self {
        RuntimeError::Io(e)
    }
}

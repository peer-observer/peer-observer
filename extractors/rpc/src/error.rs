use shared::async_nats;
use shared::async_nats::ConnectErrorKind;
use shared::corepc_client::client_sync::Error as RPCError;
use shared::log::SetLoggerError;
use std::error;
use std::fmt;
use std::io;
use std::time::SystemTimeError;

use shared::corepc_client::types::v30::GetOrphanTxsVerboseTwoEntryError;

#[derive(Debug)]
pub enum FetchOrPublishError {
    Rpc(RPCError),
    SystemTime(SystemTimeError),
    NatsPublish(async_nats::error::Error<async_nats::client::PublishErrorKind>),
    OrphanTxsModel(GetOrphanTxsVerboseTwoEntryError),
}

impl fmt::Display for FetchOrPublishError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FetchOrPublishError::Rpc(e) => write!(f, "RPC error: {}", e),
            FetchOrPublishError::SystemTime(e) => write!(f, "system time error {}", e),
            FetchOrPublishError::NatsPublish(e) => write!(f, "NATS publish error {}", e),
            FetchOrPublishError::OrphanTxsModel(e) => {
                write!(f, "model error for `getorphantxs` RPC: {}", e)
            }
        }
    }
}

impl error::Error for FetchOrPublishError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            FetchOrPublishError::Rpc(ref e) => Some(e),
            FetchOrPublishError::SystemTime(ref e) => Some(e),
            FetchOrPublishError::NatsPublish(ref e) => Some(e),
            FetchOrPublishError::OrphanTxsModel(ref e) => Some(e),
        }
    }
}

impl From<RPCError> for FetchOrPublishError {
    fn from(e: RPCError) -> Self {
        FetchOrPublishError::Rpc(e)
    }
}

impl From<SystemTimeError> for FetchOrPublishError {
    fn from(e: SystemTimeError) -> Self {
        FetchOrPublishError::SystemTime(e)
    }
}

impl From<async_nats::error::Error<async_nats::client::PublishErrorKind>> for FetchOrPublishError {
    fn from(e: async_nats::error::Error<async_nats::client::PublishErrorKind>) -> Self {
        FetchOrPublishError::NatsPublish(e)
    }
}

impl From<GetOrphanTxsVerboseTwoEntryError> for FetchOrPublishError {
    fn from(e: GetOrphanTxsVerboseTwoEntryError) -> Self {
        FetchOrPublishError::OrphanTxsModel(e)
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    SetLogger(SetLoggerError),
    Io(io::Error),
    Corepc(shared::corepc_client::client_sync::Error),
    NatsConnect(shared::async_nats::error::Error<ConnectErrorKind>),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RuntimeError::SetLogger(e) => write!(f, "set logger error {}", e),
            RuntimeError::Io(e) => write!(f, "IO error {}", e),
            RuntimeError::Corepc(e) => write!(f, "RPC client error {}", e),
            RuntimeError::NatsConnect(e) => write!(f, "NATS connection error {}", e),
        }
    }
}

impl error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            RuntimeError::SetLogger(ref e) => Some(e),
            RuntimeError::Io(ref e) => Some(e),
            RuntimeError::Corepc(ref e) => Some(e),
            RuntimeError::NatsConnect(ref e) => Some(e),
        }
    }
}

impl From<SetLoggerError> for RuntimeError {
    fn from(e: SetLoggerError) -> Self {
        RuntimeError::SetLogger(e)
    }
}

impl From<io::Error> for RuntimeError {
    fn from(e: io::Error) -> Self {
        RuntimeError::Io(e)
    }
}

impl From<shared::corepc_client::client_sync::Error> for RuntimeError {
    fn from(e: shared::corepc_client::client_sync::Error) -> Self {
        RuntimeError::Corepc(e)
    }
}

impl From<shared::async_nats::error::Error<ConnectErrorKind>> for RuntimeError {
    fn from(e: shared::async_nats::error::Error<ConnectErrorKind>) -> Self {
        RuntimeError::NatsConnect(e)
    }
}

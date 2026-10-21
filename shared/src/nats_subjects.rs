use std::fmt;

const NATS_SUBJECT_MEMPOOL: &str = "mempool";
const NATS_SUBJECT_NETMSG: &str = "netmsg";
const NATS_SUBJECT_NETCONN: &str = "netconn";
const NATS_SUBJECT_VALIDATION: &str = "validation";
const NATS_SUBJECT_RPC: &str = "rpc";
const NATS_SUBJECT_IPC: &str = "ipc";
const NATS_SUBJECT_P2P_EXTRACTOR: &str = "p2p-extractor";
const NATS_SUBJECT_LOG_EXTRACTOR: &str = "log-extractor";

#[derive(Clone, Copy)]
pub enum Subject {
    Mempool,
    NetMsg,
    NetConn,
    Validation,
    Rpc,
    Ipc,
    P2PExtractor,
    LogExtractor,
}

impl Subject {
    /// The subject name. Borrowed, so that using it doesn't allocate.
    pub fn as_str(&self) -> &'static str {
        match self {
            Subject::Mempool => NATS_SUBJECT_MEMPOOL,
            Subject::NetConn => NATS_SUBJECT_NETCONN,
            Subject::NetMsg => NATS_SUBJECT_NETMSG,
            Subject::Validation => NATS_SUBJECT_VALIDATION,
            Subject::Rpc => NATS_SUBJECT_RPC,
            Subject::Ipc => NATS_SUBJECT_IPC,
            Subject::P2PExtractor => NATS_SUBJECT_P2P_EXTRACTOR,
            Subject::LogExtractor => NATS_SUBJECT_LOG_EXTRACTOR,
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

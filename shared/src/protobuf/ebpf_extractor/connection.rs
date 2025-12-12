use crate::protobuf::bitcoin_primitives::ConnType;
use crate::protobuf::ebpf_extractor::ctypes;

use std::fmt;

// structs are generated via the connection.proto file
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.connection.rs"));

impl From<ctypes::Connection> for Connection {
    fn from(conn: ctypes::Connection) -> Self {
        let conn_type: ConnType = conn.conn_type().into();
        Connection {
            peer_id: conn.id,
            addr: conn.addr(),
            conn_type: conn_type as i32,
            network: conn.network,
        }
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(id={}, addr={}, conn_type={}, network={})",
            self.peer_id, self.addr, self.conn_type, self.network,
        )
    }
}

impl fmt::Display for ClosedConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ClosedConnection(conn={}, time_established={})",
            self.conn, self.time_established
        )
    }
}

impl From<ctypes::ClosedConnection> for ClosedConnection {
    fn from(cconn: ctypes::ClosedConnection) -> Self {
        ClosedConnection {
            conn: cconn.connection.into(),
            time_established: cconn.time_established,
        }
    }
}

impl fmt::Display for EvictedInboundConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EvictedInboundConnection(conn={}, time_established={})",
            self.conn, self.time_established
        )
    }
}

impl From<ctypes::ClosedConnection> for EvictedInboundConnection {
    fn from(econn: ctypes::ClosedConnection) -> Self {
        EvictedInboundConnection {
            conn: econn.connection.into(),
            time_established: econn.time_established,
        }
    }
}

impl fmt::Display for InboundConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "InboundConnection(conn={}, existing_connections={})",
            self.conn, self.existing_connections
        )
    }
}

impl From<ctypes::InboundConnection> for InboundConnection {
    fn from(iconn: ctypes::InboundConnection) -> Self {
        InboundConnection {
            conn: iconn.connection.into(),
            existing_connections: iconn.existing_connections,
        }
    }
}

impl fmt::Display for OutboundConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OutboundConnection(conn={}, existing_connections={})",
            self.conn, self.existing_connections
        )
    }
}

impl From<ctypes::OutboundConnection> for OutboundConnection {
    fn from(oconn: ctypes::OutboundConnection) -> Self {
        OutboundConnection {
            conn: oconn.connection.into(),
            existing_connections: oconn.existing_connections,
        }
    }
}

impl fmt::Display for MisbehavingConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MisbehavingConnection(id={}, message={})",
            self.id, self.message
        )
    }
}

impl From<ctypes::MisbehavingConnection> for MisbehavingConnection {
    fn from(mconn: ctypes::MisbehavingConnection) -> Self {
        MisbehavingConnection {
            id: mconn.id,
            message: mconn.message(),
        }
    }
}

impl fmt::Display for connection_event::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            connection_event::Event::Closed(closed) => write!(f, "{}", closed),
            connection_event::Event::InboundEvicted(evicted) => write!(f, "{}", evicted),
            connection_event::Event::Inbound(inbound) => write!(f, "{}", inbound),
            connection_event::Event::Outbound(outbound) => write!(f, "{}", outbound),
            connection_event::Event::Misbehaving(misbehaving) => {
                write!(f, "{}", misbehaving)
            }
        }
    }
}

impl fmt::Display for ConnectionEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.event {
            Some(event) => write!(f, "{}", event),
            None => write!(f, "ConnectionEvent(None)"),
        }
    }
}

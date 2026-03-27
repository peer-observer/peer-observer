use shared::{
    corepc_node,
    log::{self, info},
    nats_util::NatsArgs,
    simple_logger::SimpleLogger,
};

use std::net::TcpListener;
use std::sync::Once;

use rpc_extractor::Args;

/// Get an available port for the metrics server.
pub fn get_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port 0")
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}

static INIT: Once = Once::new();

// 1 second query interval for fast tests
pub const QUERY_INTERVAL_SECONDS: u64 = 1;

pub fn setup() {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

#[derive(Default)]
pub struct EnabledRPCsInTest {
    pub getpeerinfo: bool,
    pub getmempoolinfo: bool,
    pub uptime: bool,
    pub getnettotals: bool,
    pub getmemoryinfo: bool,
    pub getaddrmaninfo: bool,
    pub getchaintxstats: bool,
    pub getnetworkinfo: bool,
    pub getblockchaininfo: bool,
    pub getorphantxs: bool,
    pub getrawaddrman: bool,
    pub estimatesmartfee: bool,
}

#[allow(dead_code)]
impl EnabledRPCsInTest {
    /// Returns an instance with all RPC methods enabled.
    pub fn all() -> Self {
        Self {
            getpeerinfo: true,
            getmempoolinfo: true,
            uptime: true,
            getnettotals: true,
            getmemoryinfo: true,
            getaddrmaninfo: true,
            getchaintxstats: true,
            getnetworkinfo: true,
            getblockchaininfo: true,
            getorphantxs: true,
            getrawaddrman: true,
            estimatesmartfee: true,
        }
    }

    /// Returns the names of the enabled RPC methods.
    /// no need to update a separate list when adding new RPCs.
    pub fn enabled_methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        if self.getpeerinfo {
            methods.push("getpeerinfo");
        }
        if self.getmempoolinfo {
            methods.push("getmempoolinfo");
        }
        if self.uptime {
            methods.push("uptime");
        }
        if self.getnettotals {
            methods.push("getnettotals");
        }
        if self.getmemoryinfo {
            methods.push("getmemoryinfo");
        }
        if self.getaddrmaninfo {
            methods.push("getaddrmaninfo");
        }
        if self.getchaintxstats {
            methods.push("getchaintxstats");
        }
        if self.getnetworkinfo {
            methods.push("getnetworkinfo");
        }
        if self.getblockchaininfo {
            methods.push("getblockchaininfo");
        }
        if self.getorphantxs {
            methods.push("getorphantxs");
        }
        if self.getrawaddrman {
            methods.push("getrawaddrman");
        }
        if self.estimatesmartfee {
            methods.push("estimatesmartfee");
        }
        methods
    }
}

pub fn make_test_args(
    nats_port: u16,
    rpc_url: String,
    cookie_file: String,
    prometheus_address: String,
    rpcs: EnabledRPCsInTest,
) -> Args {
    Args::new(
        NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        log::Level::Trace,
        rpc_url,
        cookie_file,
        QUERY_INTERVAL_SECONDS,
        QUERY_INTERVAL_SECONDS, // query_interval_less_frequent, but don't fetch less frequently in tests
        prometheus_address,
        !rpcs.getpeerinfo,
        !rpcs.getmempoolinfo,
        !rpcs.uptime,
        !rpcs.getnettotals,
        !rpcs.getmemoryinfo,
        !rpcs.getaddrmaninfo,
        !rpcs.getchaintxstats,
        !rpcs.getnetworkinfo,
        !rpcs.getblockchaininfo,
        !rpcs.getorphantxs,
        !rpcs.getrawaddrman,
        !rpcs.estimatesmartfee,
    )
}

pub fn setup_node(conf: corepc_node::Conf) -> corepc_node::Node {
    info!("env BITCOIND_EXE={:?}", std::env::var("BITCOIND_EXE"));
    info!("exe_path={:?}", corepc_node::exe_path());

    if let Ok(exe_path) = corepc_node::exe_path() {
        info!("Using bitcoind at '{}'", exe_path);
        return corepc_node::Node::with_conf(exe_path, &conf).unwrap();
    }

    info!("Trying to download a bitcoind..");
    corepc_node::Node::from_downloaded_with_conf(&conf).unwrap()
}

pub fn setup_two_connected_nodes() -> (corepc_node::Node, corepc_node::Node) {
    // node1 listens for p2p connections
    let mut node1_conf = corepc_node::Conf::default();
    node1_conf.p2p = corepc_node::P2P::Yes;
    let node1 = setup_node(node1_conf);

    // node2 connects to node1
    let mut node2_conf = corepc_node::Conf::default();
    node2_conf.p2p = node1.p2p_connect(true).unwrap();
    let node2 = setup_node(node2_conf);

    (node1, node2)
}

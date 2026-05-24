use shared::{
    bitcoind,
    log::{self, info},
    nats_util::NatsArgs,
    simple_logger::SimpleLogger,
};

use std::sync::Once;

use rpc_extractor::Args;

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
    rpc_host: String,
    cookie_file: String,
    rpcs: EnabledRPCsInTest,
) -> Args {
    Args {
        nats: NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        log_level: log::Level::Trace,
        rpc_host,
        rpc_user: None,
        rpc_password: None,
        rpc_cookie_file: Some(cookie_file),
        query_interval: QUERY_INTERVAL_SECONDS,
        query_interval_less_frequent: QUERY_INTERVAL_SECONDS,
        prometheus_address: "127.0.0.1:0".to_string(),
        disable_getpeerinfo: !rpcs.getpeerinfo,
        disable_getmempoolinfo: !rpcs.getmempoolinfo,
        disable_uptime: !rpcs.uptime,
        disable_getnettotals: !rpcs.getnettotals,
        disable_getmemoryinfo: !rpcs.getmemoryinfo,
        disable_getaddrmaninfo: !rpcs.getaddrmaninfo,
        disable_getchaintxstats: !rpcs.getchaintxstats,
        disable_getnetworkinfo: !rpcs.getnetworkinfo,
        disable_getblockchaininfo: !rpcs.getblockchaininfo,
        disable_getorphantxs: !rpcs.getorphantxs,
        disable_getrawaddrman: !rpcs.getrawaddrman,
        disable_estimatesmartfee: !rpcs.estimatesmartfee,
    }
}

pub fn setup_node(conf: bitcoind::Conf) -> bitcoind::BitcoinD {
    info!("env BITCOIND_EXE={:?}", std::env::var("BITCOIND_EXE"));
    info!("exe_path={:?}", bitcoind::exe_path());

    if let Ok(exe_path) = bitcoind::exe_path() {
        info!("Using bitcoind at '{}'", exe_path);
        return bitcoind::BitcoinD::with_conf(exe_path, &conf).unwrap();
    }

    info!("Trying to download a bitcoind..");
    bitcoind::BitcoinD::from_downloaded_with_conf(&conf).unwrap()
}

pub fn setup_two_connected_nodes() -> (bitcoind::BitcoinD, bitcoind::BitcoinD) {
    // node1 listens for p2p connections
    let mut node1_conf = bitcoind::Conf::default();
    node1_conf.p2p = bitcoind::P2P::Yes;
    let node1 = setup_node(node1_conf);

    // node2 connects to node1
    let mut node2_conf = bitcoind::Conf::default();
    node2_conf.p2p = node1.p2p_connect(true).unwrap();
    let node2 = setup_node(node2_conf);

    (node1, node2)
}

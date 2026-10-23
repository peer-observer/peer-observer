//! RPC results the rpc-extractor has to deserialize itself, because corepc's version
//! specific types don't (yet) match what the node we query returns.

use shared::bitcoind::mtype;
use shared::corepc_regtest_client::Result;
// CORE_VERSION_GREP: When updating the corepc node crate version, bump this too.
use shared::corepc_regtest_client::types::v31::{
    GetMempoolInfo as RPCGetMempoolInfo, GetMempoolInfoError,
};
use shared::corepc_regtest_client::v31::Client;
use shared::serde::Deserialize;

/// Result of the JSON-RPC method `getmempoolinfo`.
///
/// A copy of corepc's version specific type with `fullrbf` as an `Option`. Bitcoin
/// Core v31.0 deprecated the field and v32.0 only returns it when the node is started
/// with `-deprecatedrpc=fullrbf`, which made corepc fail to deserialize the whole
/// response. Everything else is converted by corepc.
///
/// Can be dropped once corepc has v32 types.
/// See https://github.com/peer-observer/peer-observer/issues/500.
#[derive(Debug, Deserialize)]
#[serde(crate = "shared::serde")]
pub struct GetMempoolInfo {
    pub loaded: bool,
    pub size: i64,
    pub bytes: i64,
    pub usage: i64,
    pub total_fee: f64,
    #[serde(rename = "maxmempool")]
    pub max_mempool: i64,
    #[serde(rename = "mempoolminfee")]
    pub mempool_min_fee: f64,
    #[serde(rename = "minrelaytxfee")]
    pub min_relay_tx_fee: f64,
    #[serde(rename = "incrementalrelayfee")]
    pub incremental_relay_fee: f64,
    #[serde(rename = "unbroadcastcount")]
    pub unbroadcast_count: i64,
    /// Only returned by Bitcoin Core v32.0 and later when started with
    /// `-deprecatedrpc=fullrbf`.
    #[serde(rename = "fullrbf")]
    pub full_rbf: Option<bool>,
    #[serde(rename = "permitbaremultisig")]
    pub permit_bare_multisig: bool,
    #[serde(rename = "maxdatacarriersize")]
    pub max_data_carrier_size: u64,
    #[serde(rename = "limitclustercount")]
    pub limit_cluster_count: i64,
    #[serde(rename = "limitclustersize")]
    pub limit_cluster_size: i64,
    pub optimal: bool,
}

impl GetMempoolInfo {
    /// Converts to the version nonspecific corepc model type.
    pub fn into_model(self) -> std::result::Result<mtype::GetMempoolInfo, GetMempoolInfoError> {
        let full_rbf = self.full_rbf;
        let mut info = RPCGetMempoolInfo {
            loaded: self.loaded,
            size: self.size,
            bytes: self.bytes,
            usage: self.usage,
            total_fee: self.total_fee,
            max_mempool: self.max_mempool,
            mempool_min_fee: self.mempool_min_fee,
            min_relay_tx_fee: self.min_relay_tx_fee,
            incremental_relay_fee: self.incremental_relay_fee,
            unbroadcast_count: self.unbroadcast_count,
            // Overwritten below, so that a `fullrbf` the node didn't report stays unset.
            full_rbf: full_rbf.unwrap_or_default(),
            permit_bare_multisig: self.permit_bare_multisig,
            max_data_carrier_size: self.max_data_carrier_size,
            limit_cluster_count: self.limit_cluster_count,
            limit_cluster_size: self.limit_cluster_size,
            optimal: self.optimal,
        }
        .into_model()?;
        info.full_rbf = full_rbf;
        Ok(info)
    }
}

/// Calls the `getmempoolinfo` RPC, tolerating a missing `fullrbf` field.
pub fn get_mempool_info(client: &Client) -> Result<GetMempoolInfo> {
    client.call("getmempoolinfo", &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::bitcoind::serde_json;
    use shared::protobuf::rpc_extractor::FeeRateExt;

    /// A real `getmempoolinfo` response from a Bitcoin Core v31.1 regtest node.
    const WITH_FULL_RBF: &str = r#"{"loaded":true,"size":0,"bytes":0,"usage":0,"total_fee":0.00000000,"maxmempool":300000000,"mempoolminfee":0.00000100,"minrelaytxfee":0.00000100,"incrementalrelayfee":0.00000100,"unbroadcastcount":0,"fullrbf":true,"permitbaremultisig":true,"maxdatacarriersize":100000,"limitclustercount":64,"limitclustersize":101000,"optimal":true}"#;

    /// The same response without `fullrbf`, which is what Bitcoin Core v32.0 and later
    /// return unless started with `-deprecatedrpc=fullrbf`.
    const WITHOUT_FULL_RBF: &str = r#"{"loaded":true,"size":0,"bytes":0,"usage":0,"total_fee":0.00000000,"maxmempool":300000000,"mempoolminfee":0.00000100,"minrelaytxfee":0.00000100,"incrementalrelayfee":0.00000100,"unbroadcastcount":0,"permitbaremultisig":true,"maxdatacarriersize":100000,"limitclustercount":64,"limitclustersize":101000,"optimal":true}"#;

    #[test]
    fn getmempoolinfo_with_full_rbf() {
        let info: GetMempoolInfo = serde_json::from_str(WITH_FULL_RBF).unwrap();
        assert_eq!(info.full_rbf, Some(true));
        assert_eq!(info.into_model().unwrap().full_rbf, Some(true));
    }

    #[test]
    fn getmempoolinfo_without_full_rbf() {
        let info: GetMempoolInfo = serde_json::from_str(WITHOUT_FULL_RBF).unwrap();
        assert_eq!(info.full_rbf, None);
        assert_eq!(info.into_model().unwrap().full_rbf, None);
    }

    /// Everything but `fullrbf` is still converted by corepc.
    #[test]
    fn getmempoolinfo_converts_the_remaining_fields() {
        let info: GetMempoolInfo = serde_json::from_str(WITHOUT_FULL_RBF).unwrap();
        let model = info.into_model().unwrap();

        assert_eq!(model.size, 0);
        assert_eq!(model.max_mempool, 300000000);
        assert_eq!(
            model.min_relay_tx_fee.unwrap().to_sat_per_vb_f64(),
            0.1,
            "a 0.00000100 BTC/kvB minrelaytxfee is 0.1 sat/vB"
        );
    }
}

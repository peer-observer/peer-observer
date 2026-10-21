use bitcoin_capnp_types::{
    capnp::{self, Error as CapnpError},
    chain_capnp::{block_info, chain_notifications},
};
use shared::{
    bitcoin::{self, consensus::Decodable, hashes::Hash},
    protobuf::{
        bitcoin_primitives::Transaction,
        ipc_extractor::{self, ipc::IpcEvent},
    },
};

/// Takes the parsed notifications.
pub type NotificationHandler = Box<dyn Fn(IpcEvent)>;

/// Receives the chain notifications of a `bitcoin-node`, parses and hands them to a handler.
pub struct ChainNotificationsServer {
    handler: NotificationHandler,
}

impl ChainNotificationsServer {
    pub fn new(handler: NotificationHandler) -> Self {
        Self { handler }
    }

    /// Hands a parsed notification to the handler.
    fn emit(&self, event: IpcEvent) {
        (self.handler)(event);
    }
}

impl chain_notifications::Server for ChainNotificationsServer {
    async fn destroy(
        self: capnp::capability::Rc<Self>,
        _: chain_notifications::DestroyParams,
        _: chain_notifications::DestroyResults,
    ) -> Result<(), CapnpError> {
        Ok(())
    }

    async fn transaction_added_to_mempool(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::TransactionAddedToMempoolParams,
        _: chain_notifications::TransactionAddedToMempoolResults,
    ) -> Result<(), CapnpError> {
        let params = params.get()?;

        let parsed_event =
            IpcEvent::TransactionAddedToMempool(ipc_extractor::TransactionAddedToMempool {
                tx: transaction_from_raw(params.get_tx()?)?,
            });

        self.emit(parsed_event);
        Ok(())
    }

    async fn transaction_removed_from_mempool(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::TransactionRemovedFromMempoolParams,
        _: chain_notifications::TransactionRemovedFromMempoolResults,
    ) -> Result<(), CapnpError> {
        let params = params.get()?;

        let parsed_event =
            IpcEvent::TransactionRemovedFromMempool(ipc_extractor::TransactionRemovedFromMempool {
                tx: transaction_from_raw(params.get_tx()?)?,
                reason: removal_reason_to_string(params.get_reason()),
            });

        self.emit(parsed_event);
        Ok(())
    }

    async fn block_connected(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::BlockConnectedParams,
        _: chain_notifications::BlockConnectedResults,
    ) -> Result<(), CapnpError> {
        let params = params.get()?;
        let role = params.get_role()?;

        let chain_state_role = ipc_extractor::ChainstateRole {
            validated: role.get_validated(),
            historical: role.get_historical(),
        };

        let parsed_event = IpcEvent::BlockConnected(ipc_extractor::BlockConnected {
            role: chain_state_role,
            block: parse_block_info(params.get_block()?)?,
        });

        self.emit(parsed_event);
        Ok(())
    }

    async fn block_disconnected(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::BlockDisconnectedParams,
        _: chain_notifications::BlockDisconnectedResults,
    ) -> Result<(), CapnpError> {
        let params = params.get()?;

        let parsed_event = IpcEvent::BlockDisconnected(ipc_extractor::BlockDisconnected {
            block: parse_block_info(params.get_block()?)?,
        });

        self.emit(parsed_event);
        Ok(())
    }

    async fn updated_block_tip(
        self: capnp::capability::Rc<Self>,
        _: chain_notifications::UpdatedBlockTipParams,
        _: chain_notifications::UpdatedBlockTipResults,
    ) -> Result<(), CapnpError> {
        self.emit(IpcEvent::UpdatedBlockTip(ipc_extractor::UpdatedBlockTip {}));
        Ok(())
    }

    async fn chain_state_flushed(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::ChainStateFlushedParams,
        _: chain_notifications::ChainStateFlushedResults,
    ) -> Result<(), CapnpError> {
        let params = params.get()?;
        let role = params.get_role()?;

        let chain_state_role = ipc_extractor::ChainstateRole {
            validated: role.get_validated(),
            historical: role.get_historical(),
        };

        let parsed_event = IpcEvent::ChainStateFlushed(ipc_extractor::ChainStateFlushed {
            role: chain_state_role,
            locator: params.get_locator()?.to_vec(),
        });

        self.emit(parsed_event);
        Ok(())
    }
}

fn parse_block_info(block: block_info::Reader) -> Result<ipc_extractor::BlockInfo, CapnpError> {
    let prev_hash = if block.has_prev_hash() {
        Some(block.get_prev_hash()?.to_vec())
    } else {
        None
    };
    Ok(ipc_extractor::BlockInfo {
        hash: block.get_hash()?.to_vec(),
        prev_hash,
        height: block.get_height(),
        chain_time_max: block.get_chain_time_max(),
    })
}

fn transaction_from_raw(raw: &[u8]) -> Result<Transaction, CapnpError> {
    let parsed = bitcoin::Transaction::consensus_decode(&mut &raw[..])
        .map_err(|e| CapnpError::failed(format!("tx decode failed: {e}")))?;
    let txid = parsed.compute_txid().to_byte_array().to_vec();
    let wtxid = parsed.compute_wtxid().to_byte_array().to_vec();
    Ok(Transaction {
        txid,
        wtxid,
        raw: Some(raw.to_vec()),
    })
}

/// Mirrors `MemPoolRemovalReason` and `RemovalReasonToString()` in Bitcoin Core.
fn removal_reason_to_string(reason: i32) -> String {
    match reason {
        0 => "expiry".to_string(),
        1 => "sizelimit".to_string(),
        2 => "reorg".to_string(),
        3 => "block".to_string(),
        4 => "conflict".to_string(),
        5 => "replaced".to_string(),
        other => format!("unknown({})", other),
    }
}

use bitcoin_capnp_types::{
    capnp,
    capnp::Error as CapnpError,
    capnp_rpc::{self, Disconnector, RpcSystem, rpc_twoparty_capnp, twoparty},
    chain_capnp::{self, chain::Client as ChainClient, chain_notifications},
    handler_capnp::handler::Client as HandlerClient,
    init_capnp::init::Client as InitClient,
    mining_capnp::mining::Client as MiningClient,
    proxy_capnp::{self, thread::Client as ThreadClient, thread_map::Client as ThreadMapClient},
};

use shared::{
    anyhow::Result,
    bitcoin::{self, consensus::Decodable, hashes::Hash},
    futures::AsyncReadExt,
    protobuf::{
        bitcoin_primitives,
        ipc_extractor::{
            BlockConnected, BlockDisconnected, BlockInfo, BlockTip, ChainStateFlushed,
            ChainstateRole, TransactionAddedToMempool, TransactionRemovedFromMempool,
        },
    },
    tokio::{self, net::UnixStream, task::JoinHandle},
    tokio_util,
};

use std::future::Future;
use std::pin::Pin;

pub struct IpcClient {
    pub reader: IpcReader,
    pub rpc_task: JoinHandle<Result<(), CapnpError>>,
    pub disconnector: Disconnector<rpc_twoparty_capnp::Side>,
    init: InitClient,
    thread: ThreadClient,
}

impl IpcClient {
    pub async fn connect(stream: UnixStream) -> Result<Self> {
        let (reader, writer) = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
        let network = Box::new(twoparty::VatNetwork::new(
            reader,
            writer,
            rpc_twoparty_capnp::Side::Client,
            Default::default(),
        ));

        let mut rpc_system = RpcSystem::new(network, None);
        let init: InitClient = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
        let disconnector = rpc_system.get_disconnector();
        let rpc_task = tokio::task::spawn_local(rpc_system);

        let thread_map: ThreadMapClient = init
            .construct_request()
            .send()
            .promise
            .await?
            .get()?
            .get_thread_map()?;
        let thread: ThreadClient = thread_map
            .make_thread_request()
            .send()
            .promise
            .await?
            .get()?
            .get_result()?;

        let mut req = init.make_mining_request();
        set_context(req.get().get_context()?, &thread);
        let mining: MiningClient = req.send().promise.await?.get()?.get_result()?;

        let reader = IpcReader {
            mining,
            thread: thread.clone(),
        };

        Ok(Self {
            reader,
            rpc_task,
            disconnector,
            init,
            thread,
        })
    }

    pub async fn subscribe_chain_notifications(
        &self,
        callbacks: ChainCallbacks,
    ) -> Result<IpcListener> {
        let mut req = self.init.make_chain_request();
        set_context(req.get().get_context()?, &self.thread);
        let chain: ChainClient = req.send().promise.await?.get()?.get_result()?;

        let mut req = chain.handle_notifications_request();
        set_context(req.get().get_context()?, &self.thread);
        req.get()
            .set_notifications(capnp_rpc::new_client(ChainNotificationsImpl { callbacks }));
        let handler: HandlerClient = req.send().promise.await?.get()?.get_result()?;

        Ok(IpcListener {
            handler,
            thread: self.thread.clone(),
        })
    }
}

#[derive(Clone)]
pub struct IpcReader {
    pub mining: MiningClient,
    pub thread: ThreadClient,
}

impl IpcReader {
    pub async fn get_tip(&self) -> Result<Option<BlockTip>> {
        let mut req = self.mining.get_tip_request();
        set_context(req.get().get_context()?, &self.thread);
        let response = req.send().promise.await?;

        let has_result = response.get()?.get_has_result();
        if !has_result {
            return Ok(None);
        }

        let tip = response.get()?.get_result()?;
        let height = tip.get_height();
        let hash = tip.get_hash()?.to_vec();

        Ok(Some(BlockTip { height, hash }))
    }
}

pub struct IpcListener {
    pub handler: HandlerClient,
    pub thread: ThreadClient,
}

impl IpcListener {
    pub async fn shutdown(&self) -> Result<()> {
        let mut req = self.handler.disconnect_request();
        set_context(req.get().get_context()?, &self.thread);
        req.send().promise.await?;
        Ok(())
    }
}

pub type EventFut = Pin<Box<dyn Future<Output = ()>>>;

pub struct ChainCallbacks {
    pub on_block_connected: Box<dyn Fn(BlockConnected) -> EventFut>,
    pub on_block_disconnected: Box<dyn Fn(BlockDisconnected) -> EventFut>,
    pub on_tx_added: Box<dyn Fn(TransactionAddedToMempool) -> EventFut>,
    pub on_tx_removed: Box<dyn Fn(TransactionRemovedFromMempool) -> EventFut>,
    pub on_chain_state_flushed: Box<dyn Fn(ChainStateFlushed) -> EventFut>,
    pub on_updated_block_tip: Box<dyn Fn() -> EventFut>,
}

struct ChainNotificationsImpl {
    callbacks: ChainCallbacks,
}

impl chain_notifications::Server for ChainNotificationsImpl {
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
        let tx = parse_transaction(params.get()?.get_tx()?)?;
        (self.callbacks.on_tx_added)(TransactionAddedToMempool { tx }).await;
        Ok(())
    }

    async fn transaction_removed_from_mempool(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::TransactionRemovedFromMempoolParams,
        _: chain_notifications::TransactionRemovedFromMempoolResults,
    ) -> Result<(), CapnpError> {
        let r = params.get()?;
        let tx = parse_transaction(r.get_tx()?)?;
        let reason = r.get_reason();
        (self.callbacks.on_tx_removed)(TransactionRemovedFromMempool { tx, reason }).await;
        Ok(())
    }

    async fn block_connected(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::BlockConnectedParams,
        _: chain_notifications::BlockConnectedResults,
    ) -> Result<(), CapnpError> {
        let r = params.get()?;
        let role = parse_chainstate_role(r.get_role()?);
        let block = parse_block_info(r.get_block()?)?;
        (self.callbacks.on_block_connected)(BlockConnected { role, block }).await;
        Ok(())
    }

    async fn block_disconnected(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::BlockDisconnectedParams,
        _: chain_notifications::BlockDisconnectedResults,
    ) -> Result<(), CapnpError> {
        let block = parse_block_info(params.get()?.get_block()?)?;
        (self.callbacks.on_block_disconnected)(BlockDisconnected { block }).await;
        Ok(())
    }

    async fn updated_block_tip(
        self: capnp::capability::Rc<Self>,
        _: chain_notifications::UpdatedBlockTipParams,
        _: chain_notifications::UpdatedBlockTipResults,
    ) -> Result<(), CapnpError> {
        (self.callbacks.on_updated_block_tip)().await;
        Ok(())
    }

    async fn chain_state_flushed(
        self: capnp::capability::Rc<Self>,
        params: chain_notifications::ChainStateFlushedParams,
        _: chain_notifications::ChainStateFlushedResults,
    ) -> Result<(), CapnpError> {
        let r = params.get()?;
        let role = parse_chainstate_role(r.get_role()?);
        let locator = r.get_locator()?.to_vec();
        (self.callbacks.on_chain_state_flushed)(ChainStateFlushed { role, locator }).await;
        Ok(())
    }
}

fn set_context(mut ctx: proxy_capnp::context::Builder<'_>, thread: &ThreadClient) {
    ctx.set_thread(thread.clone());
    ctx.set_callback_thread(thread.clone());
}

fn parse_chainstate_role(r: chain_capnp::chainstate_role::Reader<'_>) -> ChainstateRole {
    ChainstateRole {
        validated: r.get_validated(),
        historical: r.get_historical(),
    }
}

fn parse_block_info(r: chain_capnp::block_info::Reader<'_>) -> Result<BlockInfo, CapnpError> {
    Ok(BlockInfo {
        height: r.get_height(),
        hash: r.get_hash()?.to_vec(),
        prev_hash: r.get_prev_hash()?.to_vec(),
        chain_time_max: Some(r.get_chain_time_max()),
    })
}

fn parse_transaction(raw: &[u8]) -> Result<bitcoin_primitives::Transaction, CapnpError> {
    let parsed = bitcoin::Transaction::consensus_decode(&mut &raw[..])
        .map_err(|e| CapnpError::failed(format!("tx decode failed: {e}")))?;
    let txid = parsed.compute_txid().to_byte_array().to_vec();
    let wtxid = parsed.compute_wtxid().to_byte_array().to_vec();
    Ok(bitcoin_primitives::Transaction {
        txid,
        wtxid,
        raw: Some(raw.to_vec()),
    })
}

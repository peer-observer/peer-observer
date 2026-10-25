use bitcoin_capnp_types::{
    capnp::Error as CapnpError,
    capnp_rpc::{self, Disconnector, RpcSystem, rpc_twoparty_capnp, twoparty},
    chain_capnp::chain,
    handler_capnp::handler,
    init_capnp::init,
    mining_capnp::mining,
};

use shared::{
    anyhow::{Context, Result},
    futures::AsyncReadExt,
    log,
    protobuf::ipc_extractor::BlockTip,
    tokio::{self, net::UnixStream, task::JoinHandle},
    tokio_util,
};

use crate::chain_notifications::{ChainNotificationsServer, NotificationHandler};

pub struct Connection {
    rpc_task: JoinHandle<Result<(), CapnpError>>,
    disconnector: Disconnector<rpc_twoparty_capnp::Side>,
}

impl Connection {
    fn new(
        rpc_task: JoinHandle<Result<(), CapnpError>>,
        disconnector: Disconnector<rpc_twoparty_capnp::Side>,
    ) -> Self {
        Self {
            rpc_task,
            disconnector,
        }
    }

    pub async fn closed(&mut self) -> Result<()> {
        match (&mut self.rpc_task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e).context("the IPC connection failed"),
            Err(e) => Err(e).context("the IPC task panicked or was cancelled"),
        }
    }

    pub async fn shutdown(&mut self) {
        if let Err(e) = (&mut self.disconnector).await {
            log::error!("could not run disconnector during shutdown: {}", e);
        }
        if !self.rpc_task.is_finished() {
            let _ = (&mut self.rpc_task).await;
        }
    }
}

pub async fn connect_stream(stream: UnixStream) -> Result<(IpcClient, Connection)> {
    let (reader, writer) = tokio_util::compat::TokioAsyncReadCompatExt::compat(stream).split();
    let network = Box::new(twoparty::VatNetwork::new(
        reader,
        writer,
        rpc_twoparty_capnp::Side::Client,
        Default::default(),
    ));

    let mut rpc_system = RpcSystem::new(network, None);
    let init_client: init::Client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
    let disconnector = rpc_system.get_disconnector();
    let rpc_task = tokio::task::spawn_local(rpc_system);

    let conn = Connection::new(rpc_task, disconnector);
    let ipc = IpcClient::new(init_client).await?;

    Ok((ipc, conn))
}

/// Client for the interfaces a `bitcoin-node` connection exposes once. Methods are named
/// `<interface>_<method>` after the Cap'n Proto method they call.
pub struct IpcClient {
    mining: mining::Client,
    chain: chain::Client,
    notifications_handler: Option<handler::Client>,
}

impl IpcClient {
    async fn new(init_client: init::Client) -> Result<Self> {
        let construct = init_client.construct_request().send();
        let thread_map = construct.pipeline.get_thread_map();

        let mut req = thread_map.make_pool_request();
        req.get().set_count(3); // create a pool of 3 threads on the server.
        let make_pool = req.send();

        let req = init_client.make_mining_request();
        let make_mining = req.send();
        let mining = make_mining.pipeline.get_result();

        let req = init_client.make_chain_request();
        let make_chain = req.send();
        let chain = make_chain.pipeline.get_result();

        construct.promise.await?;
        make_pool.promise.await?;

        // construct mining and chain.
        make_mining.promise.await?;
        make_chain.promise.await?;

        Ok(Self {
            mining,
            chain,
            notifications_handler: None, // set by `chain_handle_notifications`.
        })
    }

    pub async fn chain_handle_notifications(&mut self, handler: NotificationHandler) -> Result<()> {
        let mut req = self.chain.handle_notifications_request();
        req.get()
            .set_notifications(capnp_rpc::new_client(ChainNotificationsServer::new(
                handler,
            )));
        let response = req.send().promise.await?;

        self.notifications_handler = Some(response.get()?.get_result()?);
        Ok(())
    }

    pub async fn mining_get_tip(&self) -> Result<Option<BlockTip>> {
        let req = self.mining.get_tip_request();

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

    /// Destroys the notification handler on the node, then releases the remaining
    /// capabilities. Must be called before the IPC connection is shut down.
    pub async fn release(self) -> Result<()> {
        // Destroying the handler unregisters the notification proxy from the node's
        // validation signals and releases its reference to this server.
        if let Some(handler) = self.notifications_handler {
            handler.destroy_request().send().promise.await?;
        }
        Ok(())
    }
}

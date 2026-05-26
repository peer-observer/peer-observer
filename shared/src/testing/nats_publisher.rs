pub struct NatsPublisherForTesting {
    client: async_nats::Client,
}

impl NatsPublisherForTesting {
    pub async fn new(port: u16) -> Self {
        let addr = format!("127.0.0.1:{}", port);
        log::debug!("The testing NATS publisher is connecting to {}..", addr);
        Self {
            client: async_nats::connect(addr)
                .await
                .expect("should be able to connect to NATS server"),
        }
    }

    pub async fn publish(&self, subject: String, payload: Vec<u8>) {
        log::trace!("publishing {} ({} bytes)", subject, payload.len());
        self.client
            .publish(subject, payload.into())
            .await
            .expect("should be able to publish");
    }
}

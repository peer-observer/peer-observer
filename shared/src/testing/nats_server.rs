// This file includes code from rants (https://github.com/davidMcneil/rants/)
// Copyright (c) 2021 David McNeil and contributors
// Licensed under the MIT License: https://opensource.org/licenses/MIT
//
// Modifications to
// https://github.com/davidMcneil/rants/blob/beb187b49bd6ade187cb5b92023cb67ba0e15baa/tests/common.rs:
// - Renamed NATS_PATH_ENV to ENV_NATS_SERVER_BINARY
// - Renamed NatsServer to NatsServerForTesting
// - Changed the function new() to attempt to find a working port for NATS and hardcode all other nats-server args

use rand::Rng;
use std::{env, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::oneshot::{self, Sender},
    time::timeout,
};

const PORT_ATTEMPTS: usize = 10;

const ENV_NATS_SERVER_BINARY: &str = "NATS_SERVER_BINARY";
const NATS_READY_MESSAGE: &str = "Server is ready";
const NATS_PORT_IN_USE_MESSAGE: &str = "address already in use";

pub struct NatsServerForTesting {
    kill: Option<Sender<()>>,
    pub port: u16,
}

impl NatsServerForTesting {
    pub async fn new() -> Self {
        let nats_server_binary_path: String = match env::var(ENV_NATS_SERVER_BINARY) {
            Ok(b) => b,
            Err(e) => {
                panic!(
                "Set the {} environment variable to the location of your nats-server binary run the integration tests: {}",
                ENV_NATS_SERVER_BINARY, e
            );
            }
        };

        for attempt in 1..=PORT_ATTEMPTS {
            let mut rng = rand::rng();
            let nats_port = rng.random_range(49152..65500);

            log::debug!(
                "attempting to use port={} for the testing NATS server (attempt={})",
                nats_port,
                attempt
            );
            let args = [&format!("--port={}", nats_port), "--addr=127.0.0.1"];

            log::info!(
                "Starting NATS server with: {} {}",
                nats_server_binary_path,
                args.join(" ")
            );

            let mut child = Command::new(nats_server_binary_path.clone())
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to start nats-server with binary='{}' and args='{}'",
                        nats_server_binary_path,
                        args.join(" ")
                    )
                });

            // Spawn a task to handle stdout
            let stdout = child
                .stdout
                .take()
                .expect("child did not have a handle to stdout");
            tokio::spawn(async {
                let mut reader = BufReader::new(stdout).lines();
                while let Some(line) = reader.next_line().await.expect("valid stdout line") {
                    log::info!("{}", line);
                }
            });

            // Spawn a task to handle stderr and check if nats is ready
            let (ready_tx, ready_rx) = oneshot::channel::<bool>();
            let stderr = child
                .stderr
                .take()
                .expect("child did not have a handle to stdout");
            tokio::spawn(async {
                let mut ready_tx = Some(ready_tx);
                let mut reader = BufReader::new(stderr).lines();
                while let Some(line) = reader.next_line().await.expect("valid stdout line") {
                    log::debug!("{}", line);
                    if line.contains(NATS_READY_MESSAGE) {
                        if let Some(ready_tx) = ready_tx.take() {
                            ready_tx.send(true).expect("to send nats ready oneshot");
                        }
                    }
                    if line.contains(NATS_PORT_IN_USE_MESSAGE) {
                        if let Some(ready_tx) = ready_tx.take() {
                            ready_tx.send(false).expect("to send nats ready oneshot");
                        }
                    }
                }
            });

            // Spawn a task to run the child and wait for the kill oneshot
            let (kill_tx, kill_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                tokio::select! {
                    exit = child.wait()  => {
                        if let Err(e) = exit {
                            panic!("NATS produced Err while running: {}", e);
                        } else {
                            // We might right reach this if the port is alrady in use..
                            // This is handled below.
                            log::debug!("NATS exited on it's own before we killed it: {:?}", exit);
                        }
                    }
                    rx = kill_rx => {
                        if rx.is_err() {
                            panic!("failed to receive ready oneshot");
                        } else {
                            ();
                        }
                    }
                }
            });

            // Wait for NATS to be ready or timeout
            match timeout(Duration::from_secs(5), ready_rx).await {
                Ok(ready) => {
                    if ready.unwrap() {
                        return Self {
                            kill: Some(kill_tx),
                            port: nats_port,
                        };
                    } else {
                        log::warn!("NATS port already in use - trying again with another one");
                        continue;
                    }
                }
                Err(e) => {
                    log::warn!(
                        "NATS server failed to reach ready state within timeout: {}",
                        e
                    );
                }
            }
        }
        panic!("Could not spawn NATS server")
    }
}

impl Drop for NatsServerForTesting {
    fn drop(&mut self) {
        if let Some(kill) = self.kill.take() {
            kill.send(()).expect("to send kill oneshot")
        }
    }
}

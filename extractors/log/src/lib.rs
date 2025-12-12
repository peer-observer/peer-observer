use error::RuntimeError;
use shared::async_nats::{self};
use shared::clap;
use shared::clap::Parser;
use shared::log;
use shared::log_matchers::parse_log_event;
use shared::nats_subjects::Subject;
use shared::prost::Message;
use shared::protobuf::event_msg::EventMsg;
use shared::protobuf::event_msg::event_msg::Event;
use shared::tokio::{
    self,
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, BufReader},
    sync::watch,
    time,
};

mod error;

// from libc crate
pub const O_NONBLOCK: i32 = 2048;

/// The peer-observer log-extractor reads lines from a pipe to a Bitcoin node
/// debug.log pipe (named pipe / FIFO) and publishes parsed lines as events
/// into a NATS pub-sub queue.
#[derive(Parser, Debug)]
#[clap(group(
    clap::ArgGroup::new("pipe")
        .required(true)
        .multiple(false)
        .args(&["bitcoind_pipe"]),
))]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Address of the NATS server where the extractor will publish messages to.
    #[arg(short, long, default_value = "127.0.0.1:4222")]
    pub nats_address: String,

    /// Path to the bitcoind log pipe (named pipe / FIFO).
    #[arg(short, long)]
    pub bitcoind_pipe: String,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html.
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,
}

impl Args {
    pub fn new(nats_address: String, bitcoind_pipe: String, log_level: log::Level) -> Args {
        Self {
            nats_address,
            bitcoind_pipe,
            log_level,
        }
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    log::debug!("Connecting to NATS server at {}...", &args.nats_address);
    let nats_client = async_nats::connect(&args.nats_address).await?;
    log::info!("Connected to NATS server at {}", &args.nats_address);

    log::info!("Opening bitcoind log pipe at {}...", &args.bitcoind_pipe);
    let file = open_pipe(&args.bitcoind_pipe, shutdown_rx.clone()).await?;
    log::info!("Opened bitcoind log pipe at {}", &args.bitcoind_pipe);
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    log::info!(
        "Started reading lines from bitcoind log pipe at {}",
        &args.bitcoind_pipe
    );
    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(line)) => process_log(&nats_client, &line).await,
                    Ok(None) => {
                        // Since we use O_NONBLOCK, we need to wait here for a
                        // bit to avoid spinning here if we don't have anything
                        // to read.
                        time::sleep(time::Duration::from_millis(25)).await;
                    },
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // Non-blocking read with no data available: briefly
                            // sleep to avoid spinning here and then continue.
                            time::sleep(time::Duration::from_millis(25)).await;
                            continue;
                        }
                        return Err(e.into());
                    }
                }
            },
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("log-extractor received shutdown signal.");
                            break;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn process_log(nats_client: &async_nats::Client, line: &str) {
    log::trace!("Read log line: {}", line);
    match EventMsg::new(Event::LogExtractor(parse_log_event(line))) {
        Ok(proto) => {
            if let Err(e) = nats_client
                .publish(
                    Subject::LogExtractor.to_string(),
                    proto.encode_to_vec().into(),
                )
                .await
            {
                log::error!("could not publish log into NATS: {}", e);
            } else {
                log::trace!("published log into NATS: {:?}", proto);
            }
        }
        Err(e) => {
            log::error!(
                "Could not create new EventMsg due to SystemTimeError: {}",
                e
            );
        }
    };
}

async fn open_pipe(path: &str, shutdown_rx: watch::Receiver<bool>) -> Result<File, std::io::Error> {
    // Fail after MAX_RETRIES if the pipe doesn't exist yet.
    const MAX_RETRIES: i32 = 30;
    for retries in 0..=MAX_RETRIES {
        if *shutdown_rx.borrow() {
            log::info!("open_pipe received shutdown signal.");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "shutdown signal received",
            ));
        }

        if !std::path::Path::new(path).exists() {
            log::warn!(
                "Pipe {} does not exist yet, retrying in 1s (retry: {}/{})",
                path,
                retries,
                MAX_RETRIES
            );
            time::sleep(time::Duration::from_secs(1)).await;
        } else {
            break;
        }
    }

    OpenOptions::new()
        .read(true)
        .write(false)
        // We need to use O_NONBLOCK here, otherwise a pipe without a writer
        // will block the tokio async routine on next_line() and we can't
        // e.g. CTRL+C anymore.
        .custom_flags(O_NONBLOCK)
        .open(path)
        .await
}

use ebpf_extractor::Args;
use shared::log;
use shared::tokio;
use shared::clap::Parser;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = ebpf_extractor::run(args).await {
        log::error!("Fatal error during extractor runtime: {}", e);
    }
}

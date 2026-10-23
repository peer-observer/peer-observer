use archive::archiveinfo::{self, Args};
use shared::anyhow::{Context, Result};
use shared::clap::Parser;
use shared::simple_logger;

fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    if archiveinfo::run(&args, &mut std::io::stdout().lock())? {
        std::process::exit(1);
    }

    Ok(())
}

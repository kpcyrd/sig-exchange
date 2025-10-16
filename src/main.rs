mod args;
mod debian;
mod errors;
mod plumbing;
mod sig;
mod srcinfo;

use crate::args::Args;
use crate::errors::*;
use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let log_level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    trace!("Args: {args:#?}");
    match args.subcommand {
        args::SubCommand::Plumbing(plumbing) => plumbing::run(plumbing).await,
    }
}

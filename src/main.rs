mod archlinux;
mod args;
mod db;
mod debian;
mod errors;
mod fetch;
mod import;
mod issuer;
mod pgp;
mod pkg;
mod plumbing;
mod sig;
mod srcinfo;
mod web;

use crate::args::Args;
use crate::errors::*;
use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let log_level = match args.verbose {
        0 => "info",
        1 => "sig_exchange=debug,info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    dotenvy::dotenv().ok();

    trace!("Args: {args:#?}");
    match args.subcommand {
        args::SubCommand::Web(web) => web::run(&web).await,
        args::SubCommand::Import(import) => import::run(&import).await,
        args::SubCommand::Plumbing(plumbing) => plumbing::run(plumbing).await,
    }
}

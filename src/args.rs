use clap::{ArgAction, Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    #[command(alias = "daemon")]
    Web(Web),
    #[command(subcommand)]
    Import(Import),
    #[command(subcommand)]
    Plumbing(Plumbing),
}

/// Run the web server daemon
#[derive(Debug, Parser)]
pub struct Web {
    #[arg(short = 'B', long, env)]
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Parser)]
pub enum Import {
    ArchlinuxTar { path: PathBuf },
    PgpSigs { path: PathBuf },
}

#[derive(Debug, Parser)]
pub enum Plumbing {
    ArchlinuxTar { path: PathBuf },
    DebSrc { path: PathBuf },
    DebianTar { path: PathBuf },
    Migrate,
    PgpSigs { path: PathBuf },
    PingDb,
    Srcinfo { path: PathBuf },
}

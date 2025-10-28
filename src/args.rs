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

/// Run the data importer
#[derive(Debug, Parser)]
pub enum Import {
    /// Import an Arch Linux PKGBUILD tar snapshot
    ArchlinuxTar { path: PathBuf },
    /// Import the Arch Linux package database tree
    ArchlinuxTree,
    /// Import Debian Sources package database tree
    DebianSources,
    /// Import PGP signatures
    PgpSigs { path: PathBuf },
}

/// Low-level debugging and testing commands for development
#[derive(Debug, Parser)]
pub enum Plumbing {
    /// Parse an Arch Linux PKGBUILD tar snapshot
    ArchlinuxTar { path: PathBuf },
    /// Parse a Debian Sources index file
    DebSrc { path: PathBuf },
    /// Parse a Debian source package tar archive
    DebianTar { path: PathBuf },
    /// Fetch a URL using the HTTP cache and display the number of bytes received
    FetchCache { url: String },
    /// Fetch pending remote signatures from the queue
    FetchSigQueue,
    /// Run database migrations
    Migrate,
    /// Parse a PGP public key file
    PgpKeys { path: PathBuf },
    /// Parse a PGP signature file
    PgpSigs { path: PathBuf },
    /// Test database connectivity
    PingDb,
    /// Parse an Arch Linux SRCINFO file
    Srcinfo { path: PathBuf },
}

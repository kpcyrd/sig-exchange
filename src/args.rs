use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SubCommand {
    #[command(subcommand)]
    Plumbing(Plumbing),
}

#[derive(Debug, Clone, Parser)]
pub enum Plumbing {
    ArchlinuxTar { path: PathBuf },
    DebSrc { path: PathBuf },
    DebianTar { path: PathBuf },
    Srcinfo { path: PathBuf },
}

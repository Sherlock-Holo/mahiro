use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
pub struct Args {
    /// enable debug log
    #[arg(short, long)]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// set mahiro network whitelist route
    Setroute {
        /// mahiro nic
        #[arg(short, long)]
        nic: String,

        /// whitelist ip list file paths
        #[arg(short, long)]
        ip_list: Vec<String>,
    },

    /// clean mahiro network whitelist route
    Cleanroute,
}

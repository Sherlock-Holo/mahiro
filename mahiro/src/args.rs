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
    Mahiro {
        /// config path
        #[arg(short, long)]
        config: String,
    },

    Mihari {
        /// config path
        #[arg(short, long)]
        config: String,

        /// enable bpf mode nat
        #[arg(short, long)]
        bpf_nat: bool,
    },

    Genkey {
        /// private key file path
        #[arg(long)]
        private: String,

        /// public key file path
        #[arg(long)]
        public: String,
    },
}

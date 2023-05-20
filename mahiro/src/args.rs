use std::fmt::{Display, Formatter};

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
pub struct Args {
    /// enable debug log
    #[arg(short, long, default_value_t = LogLevel::Info)]
    pub log: LogLevel,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, ValueEnum, Default)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    None,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => f.write_str("debug"),
            LogLevel::Info => f.write_str("info"),
            LogLevel::Warn => f.write_str("warn"),
            LogLevel::Error => f.write_str("error"),
            LogLevel::None => f.write_str("none"),
        }
    }
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
        #[arg(long)]
        bpf_nat: bool,

        /// enable bpf packet redirect forward
        #[arg(long)]
        bpf_forward: bool,
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

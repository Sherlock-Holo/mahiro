#![feature(io_error_more)]
#![feature(ip)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/Sherlock-Holo/mahiro/master/mahiro.svg")]

use std::future::pending;
use std::io;
use std::num::NonZeroUsize;
use std::path::Path;
use std::thread::available_parallelism;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clap::Parser;
use ring_io::fs;
use tokio::task;
use tracing::level_filters::LevelFilter;
use tracing::subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

use self::args::{Args, Command, LogLevel};
use self::encrypt::Encrypt;
use crate::util::io_uring_builder;

mod args;
mod cookie;
mod encrypt;
mod ip_packet;
mod mahiro;
mod mihari;
mod protocol;
mod public_key;
mod tun;
mod util;

const HEARTBEAT_DATA: &[u8] = b"onimai";

fn init_log(log_level: LogLevel) {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let level = match log_level {
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::None => LevelFilter::OFF,
    };

    let layered = Registry::default().with(layer).with(level);

    subscriber::set_global_default(layered).unwrap();
}

pub async fn run() -> anyhow::Result<()> {
    let threads = available_parallelism()
        .unwrap_or(NonZeroUsize::new(4).unwrap())
        .get();
    for _ in 0..threads {
        task::spawn_blocking(|| {
            ring_io::block_on_with_io_uring_builder(pending::<()>(), &io_uring_builder())
        });
    }

    task::spawn_blocking(|| {
        ring_io::block_on_with_io_uring_builder(
            async move {
                let args = Args::parse();

                init_log(args.log);

                match args.command {
                    Command::Mahiro { config } => mahiro::run(Path::new(&config)).await,
                    Command::Mihari {
                        config,
                        bpf_nat,
                        bpf_forward,
                    } => mihari::run(Path::new(&config), bpf_nat, bpf_forward).await,
                    Command::Genkey { private, public } => {
                        generate_keypair(&private, &public).await
                    }
                }
            },
            &io_uring_builder(),
        )
    })
    .await
    .unwrap()
}

async fn generate_keypair(private: &str, public: &str) -> anyhow::Result<()> {
    let keypair = Encrypt::generate_keypair()?;

    fs::write(private, BASE64_STANDARD.encode(keypair.private))
        .await
        .0?;
    fs::write(public, BASE64_STANDARD.encode(keypair.public))
        .await
        .0?;

    Ok(())
}

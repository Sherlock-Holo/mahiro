#![feature(io_error_more)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/Sherlock-Holo/mahiro/master/mahiro.svg")]

use std::io;
use std::path::Path;

use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing::subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

use self::args::{Args, Command};

mod args;
mod encrypt;
mod mahiro;
mod mihari;
mod protocol;
mod route_table;
mod tun;
mod util;

const HEARTBEAT_DATA: &[u8] = b"onimai";

fn init_log(debug: bool) {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let layered = Registry::default().with(layer).with(level);

    subscriber::set_global_default(layered).unwrap();
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log(args.debug);

    match args.command {
        Command::Mahiro { config } => mahiro::run(Path::new(&config)).await,
    }
}

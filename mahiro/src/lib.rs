#![feature(io_error_more)]
#![feature(ip)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/Sherlock-Holo/mahiro/master/mahiro.svg")]

use std::io;
use std::path::Path;

use clap::Parser;
use time::macros::format_description;
use time::UtcOffset;
use tracing::level_filters::LevelFilter;
use tracing::subscriber;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

use self::args::{Args, Command, LogLevel};

mod args;
mod ip_packet;
mod mahiro;
mod mihari;
mod public_key;
mod tls_accept;
mod token;
mod tun;
mod util;

fn init_log(log_level: LogLevel) {
    let offset = UtcOffset::from_hms(8, 0, 0).unwrap();
    let format = format_description!(
        "[year]-[month]-[day] [hour repr:24]:[minute]:[second].[subsecond digits:6]"
    );

    let layer = fmt::layer()
        .pretty()
        .with_timer(OffsetTime::new(offset, format))
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
    let args = Args::parse();

    init_log(args.log);

    match args.command {
        Command::Mahiro { config } => mahiro::run(Path::new(&config)).await,
        Command::Mihari {
            config,
            bpf_nat,
            bpf_forward,
        } => mihari::run(Path::new(&config), bpf_nat, bpf_forward).await,
    }
}

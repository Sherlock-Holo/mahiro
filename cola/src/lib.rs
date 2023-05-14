use std::io;

use clap::Parser;
use tracing::subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};

use self::args::{Args, Command};

mod args;
mod route;

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.debug {
        init_log();
    }

    match args.command {
        Command::Setroute { nic, ip_list } => {
            route::set_route(ip_list.iter().map(|path| path.as_str()), nic).await
        }

        Command::Cleanroute => route::clean_route().await,
    }
}

fn init_log() {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let layered = Registry::default().with(layer);

    subscriber::set_global_default(layered).unwrap();
}

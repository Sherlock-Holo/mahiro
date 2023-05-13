use clap::Parser;

use self::args::{Args, Command};

mod args;
mod route;

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Setroute { nic, ip_list } => {
            route::set_route(ip_list.iter().map(|path| path.as_str()), nic).await
        }

        Command::Cleanroute => route::clean_route().await,
    }
}

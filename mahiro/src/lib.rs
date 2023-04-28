#![feature(io_error_more)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/Sherlock-Holo/mahiro/master/mahiro.svg")]

mod encrypt;
mod mahiro;
mod mihari;
mod protocol;
mod route_table;
mod tun;

const HEARTBEAT_DATA: &[u8] = b"onimai";

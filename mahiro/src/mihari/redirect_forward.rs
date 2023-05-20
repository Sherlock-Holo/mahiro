use aya::programs::xdp::XdpLink;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use tap::TapFallible;
use tracing::{error, info};

use crate::util::OwnedLink;

const XDP_REDIRECT_ROUTE: &str = "redirect_route";

pub fn enable_xdp_redirect_forward(
    bpf: &mut Bpf,
    mihari_nic: &str,
) -> anyhow::Result<OwnedLink<XdpLink>> {
    let xdp_redirect_route: &mut Xdp = bpf
        .program_mut(XDP_REDIRECT_ROUTE)
        .expect("xdp redirect route bpf program miss")
        .try_into()
        .tap_err(|err| error!(%err, "get xdp redirect route bpf program failed"))?;

    xdp_redirect_route
        .load()
        .tap_err(|err| error!(%err, "load xdp redirect route bpf program failed"))?;

    info!("load xdp redirect route bpf program done");

    let xdp_link_id = xdp_redirect_route
        .attach(mihari_nic, XdpFlags::default())
        .tap_err(|err| {
            error!(%err, mihari_nic, "attach xdp redirect route bpf program to mihari nic failed");
        })?;

    info!(
        mihari_nic,
        "attach xdp redirect route bpf program to mihari nic done"
    );

    let xdp_link = xdp_redirect_route
        .take_link(xdp_link_id)
        .tap_err(|err| error!(%err, "xdp redirect route take link failed"))?;

    Ok(OwnedLink::from(xdp_link))
}

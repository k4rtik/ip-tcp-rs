use std::net::Ipv4Addr;

pub fn handler(rip_pkt: &[u8]) {
    info!{"{:?}", rip_pkt};
}

pub fn get_next_hop(dst: Ipv4Addr) -> Ipv4Addr {
    dst
}

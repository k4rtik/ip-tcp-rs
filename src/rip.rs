use std::net::Ipv4Addr;
pub fn handler(rip_pkt: &[u8]) {
    debug!{"{:?}", &rip_pkt[..20]};
}

pub fn get_next_hop(dst: Ipv4Addr) -> Ipv4Addr {
    dst
}

pub fn get_routes() -> Vec<route> {
    let r = route {
        src: Ipv4Addr::new(127, 0, 0, 1),
        dst: Ipv4Addr::new(127, 0, 0, 1),
        cost: 0,
    };
    let mut routes = Vec::<route>::new();
    routes.push(r);
    routes
}

pub struct route {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub cost: i32,
}

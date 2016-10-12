
use std::net::Ipv4Addr;
use std::time::Duration;

use pnet_macros_support::types::*;

use datalink::{Interface, RouteInfo};

pub fn handler(rip_pkt: &[u8]) {
    debug!{"{:?}", &rip_pkt[..20]};
}

pub fn get_next_hop(dst: Ipv4Addr) -> Ipv4Addr {
    dst
}

#[derive(Debug, Clone)]
pub struct Route {
    pub dst: Ipv4Addr,
    pub src: Ipv4Addr,
    pub cost: u8,
}

struct RouteEntry {
    dst: Ipv4Addr,
    next_hop: Ipv4Addr,
    interface: Interface, // which physical interface for this route
    metric: u8, // max 16, TODO create a new type
    timer: Duration, // since last updated
    route_src: Ipv4Addr, // gateway that provided this route
    route_changed: bool,
}

#[packet]
pub struct Rip {
    command: u16be,
    num_entries: u16be,
    #[length = "num_entries * 64"]
    entries: Vec<RipEntry>,
    #[payload]
    payload: Vec<u8>, // unused
}

#[packet]
pub struct RipEntry {
    cost: u32be,
    address: u32be,
    #[payload]
    payload: Vec<u8>, // unused
}

pub struct RipCtx {
    routing_table: Vec<RouteEntry>,
}

impl RipCtx {
    pub fn new(ri: RouteInfo) -> RipCtx {
        RipCtx { routing_table: Vec::new() }
    }

    pub fn send_routing_update(&self) {}

    pub fn update_routing_table(&self) {}

    pub fn get_routes(&self) -> Vec<Route> {
        Vec::new()
    }
}

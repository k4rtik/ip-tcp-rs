use datalink::{RouteInfo, DataLink};
use ip;
use pnet::packet::{Packet, MutablePacket};

use packet::rip_pkt::{RipPacket, MutableRipPacket, RipEntryPacket, MutableRipEntryPacket};

use std::sync::{Arc, RwLock};
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};
use std::thread;

const RIP_PERIOD: u64 = 15;
const RIP_PROT: u8 = 200;
const RIP_MAX_SIZE: usize = 2 + 2 + 64 * 8; // from given packet format

pub fn handler(rip_pkt: &[u8]) {}

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
    // interface: Interface, // which physical interface for this route
    metric: u8, // max 16, TODO create a new type
    timer: SystemTime, // since last updated
    route_src: Ipv4Addr, // gateway that provided this route
    route_changed: bool,
}

pub struct RipCtx {
    routing_table: Vec<RouteEntry>,
}

impl RipCtx {
    pub fn new(ri: &RouteInfo) -> RipCtx {
        RipCtx {
            routing_table: ri.interfaces
                .iter()
                .map(|iface| {
                    RouteEntry {
                        dst: iface.src_vip,
                        next_hop: iface.src_vip,
                        metric: 0,
                        timer: SystemTime::now(),
                        route_src: iface.src_vip,
                        route_changed: true,
                    }
                })
                .collect(),
        }
    }

    pub fn get_num_entries(&self) -> usize {
        self.routing_table.len()
    }

    pub fn send_routing_update(&self) {}

    pub fn update_routing_table(&self) {}

    pub fn get_routes(&self) -> Vec<Route> {
        self.routing_table
            .iter()
            .map(|rentry| {
                Route {
                    dst: rentry.dst,
                    src: rentry.next_hop,
                    cost: rentry.metric,
                }
            })
            .collect()
    }
}

fn build_rip_entry_pkt(rip_ctx: &Arc<RwLock<RipCtx>>, entry_id: usize, packet: &mut [u8]) {
    let mut ripe_pkt = MutableRipEntryPacket::new(packet).unwrap();

    let ref entry = (*rip_ctx.read().unwrap()).get_routes()[entry_id];

    ripe_pkt.set_cost(entry.cost as u32);
    ripe_pkt.set_address(entry.dst);

    // debug!("{:?}", ripe_pkt);
}

fn build_rip_pkt(rip_ctx: &Arc<RwLock<RipCtx>>, packet: &mut [u8]) -> usize {
    let num_entries = (*rip_ctx.read().unwrap()).get_num_entries();
    {
        let mut rip_pkt = MutableRipPacket::new(packet).unwrap();

        rip_pkt.set_command(2);
        rip_pkt.set_num_entries(num_entries as u16);
    }

    let mut idx = 4;
    let mut entry_id = 0;
    while entry_id < num_entries {
        build_rip_entry_pkt(rip_ctx, entry_id, &mut packet[idx..]);
        entry_id += 1;
        idx += 8;
    }

    // rip_pkt.set_entries(&packet[2..]);
    debug!("{:?}", RipPacket::new(packet).unwrap());
    idx
}

pub fn start_rip_module(dl_ctx: &Arc<RwLock<DataLink>>, rip_ctx: &Arc<RwLock<RipCtx>>) {
    loop {
        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
        for iface in interfaces {
            let mut rip_buf = vec![0u8; RIP_MAX_SIZE];
            let pkt_size = build_rip_pkt(rip_ctx, &mut rip_buf);
            let rip_pkt = RipPacket::new(&rip_buf).unwrap();
            let ip_params = ip::IpParams {
                src: Ipv4Addr::new(127, 0, 0, 1),
                dst: iface.dst,
                len: pkt_size,
                tos: 0,
                opt: vec![],
            };
            let res = ip::send(&dl_ctx,
                               ip_params,
                               RIP_PROT,
                               16,
                               rip_pkt.packet().to_vec(),
                               0,
                               true);
            match res {
                Ok(_) => info!("RIP update sent succesfully on {:?}", iface.dst),
                Err(str) => error!("{}", str),
            }
        }
        thread::sleep(Duration::from_secs(RIP_PERIOD));
    }
}

use packet::rip_pkt::{RipPacket, MutableRipPacket, MutableRipEntryPacket};
use pnet::packet::Packet;

use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use datalink::{RouteInfo, DataLink};
use ip;

const RIP_PERIOD: u64 = 5;
const RIP_TIMEOUT: u64 = 12;
const RIP_PROT: u8 = 200;
const RIP_MAX_SIZE: usize = 2 + 2 + 64 * 8; // from given packet format
pub const INFINITY: u8 = 16;

#[derive(Debug, Clone)]
pub struct Route {
    pub dst: Ipv4Addr,
    pub src: Ipv4Addr,
    pub cost: u8,
}

#[derive(Debug)]
struct RouteEntry {
    dst: Ipv4Addr,
    next_hop: Ipv4Addr,
    // interface: Interface, // which physical interface for this route
    metric: u8,
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
                        route_changed: false,
                    }
                })
                .collect(),
        }
    }

    pub fn get_next_hop(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        match self.routing_table
            .iter()
            .find(|rentry| rentry.dst == dst && rentry.metric != INFINITY) {
            Some(re) => Some(re.next_hop),
            None => None,
        }
    }

    pub fn get_num_entries(&self) -> usize {
        self.routing_table.len()
    }

    pub fn toggle_interface_state(&mut self,
                                  dl_ctx: &Arc<RwLock<DataLink>>,
                                  local_ip: Ipv4Addr,
                                  status: bool) {
        if !status {
            // taking down local interface
            for rentry in &mut self.routing_table {
                if rentry.next_hop == local_ip {
                    rentry.metric = INFINITY;
                    rentry.timer = SystemTime::now();
                    rentry.route_src = local_ip;
                    rentry.route_changed = true;
                }
            }
        } else {
            // enabling interface
            for rentry in &mut self.routing_table {
                if rentry.dst == local_ip {
                    // TODO for non-local dst, RIP shouldn't update if local interface is down
                    rentry.metric = 0;
                    rentry.timer = SystemTime::now();
                    rentry.route_src = local_ip;
                    rentry.route_changed = true;
                }
            }
            // TODO request RIP
        }
        self.send_triggered_updates(dl_ctx, None);
    }

    fn get_and_unmark_updated_routes(&mut self) -> Vec<Route> {
        let mut ret: Vec<Route> = Vec::new();
        for rentry in &mut self.routing_table {
            if rentry.route_changed {
                rentry.route_changed = false;
                ret.push(Route {
                    dst: rentry.dst,
                    src: rentry.next_hop,
                    cost: rentry.metric,
                });
            }
        }
        ret
    }

    fn send_triggered_updates(&mut self,
                              dl_ctx: &Arc<RwLock<DataLink>>,
                              source: Option<Ipv4Addr>) {
        let mut rip_buf = vec![0u8; RIP_MAX_SIZE];

        let entries = self.get_and_unmark_updated_routes();
        let num_entries = entries.len();

        // build rip_pkt
        {
            let mut rip_pkt = MutableRipPacket::new(&mut rip_buf).unwrap();

            rip_pkt.set_command(2);
            rip_pkt.set_num_entries(num_entries as u16);
        }

        let mut idx = 4;
        // build rip_entry_pkt
        {
            let mut entry_id = 0;
            while entry_id < num_entries {
                let mut ripe_pkt = MutableRipEntryPacket::new(&mut rip_buf[idx..]).unwrap();

                let entry = &entries[entry_id];

                ripe_pkt.set_cost(entry.cost as u32);
                ripe_pkt.set_address(entry.dst);

                entry_id += 1;
                idx += 8;
            }
        }

        let pkt_size = idx;
        let rip_pkt = RipPacket::new(&rip_buf).unwrap();

        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
        for iface in interfaces {
            if Some(iface.dst) != source {
                let ip_params = ip::IpParams {
                    src: Ipv4Addr::new(127, 0, 0, 1),
                    dst: iface.dst,
                    len: pkt_size,
                    tos: 0,
                    opt: vec![],
                };
                trace!("SENDING TRIGGERED UPDATE: {:?}", rip_pkt);
                let res = ip::send(dl_ctx,
                                   None,
                                   None,
                                   ip_params,
                                   RIP_PROT,
                                   INFINITY,
                                   rip_pkt.packet().to_vec(),
                                   0,
                                   true);
                match res {
                    Ok(_) => trace!("Triggered update sent succesfully on {:?}", iface.dst),
                    Err(str) => warn!("{}", str),
                }
            }
        }
    }

    pub fn update_routing_table(&mut self,
                                dl_ctx: &Arc<RwLock<DataLink>>,
                                routes: Vec<Route>,
                                source: Option<Ipv4Addr>) {
        trace!{"Received routes for update: {:?}", routes};
        for route in routes {
            match (*dl_ctx.read().unwrap()).get_interface_by_dst(route.src) {
                Some(iface) => {
                    if !iface.enabled {
                        info!("iface for this route is down: {:?}", route);
                        continue;
                    }
                }
                None => {
                    warn!("Received a route with no matching local interface: {:?}",
                          route);
                    continue;
                }
            };
            if !route.dst.is_loopback() && !(*dl_ctx.read().unwrap()).is_local_address(route.dst) {
                if route.cost <= INFINITY {
                    let route = Route {
                        cost: if route.cost + 1 < INFINITY {
                            route.cost + 1
                        } else {
                            route.cost
                        },
                        ..route
                    };

                    let mut need_to_add = false;
                    trace!("BEFORE routing_table: {:?}", self.routing_table);
                    match self.routing_table.iter_mut().find(|rentry| rentry.dst == route.dst) {
                        Some(rentry) => {
                            rentry.metric = if route.cost < rentry.metric {
                                rentry.route_changed = true;
                                route.cost
                            } else {
                                rentry.metric
                            };
                            rentry.timer = SystemTime::now();
                            trace!("rentry: {:?}", rentry);
                        }
                        None => {
                            if route.cost < INFINITY {
                                info!("Adding new rentry");
                                need_to_add = true;
                            }
                        }
                    }
                    if need_to_add {
                        self.routing_table.push(RouteEntry {
                            dst: route.dst,
                            next_hop: (*dl_ctx.read().unwrap())
                                .get_interface_by_dst(route.src)
                                .unwrap()
                                .src,
                            metric: route.cost,
                            timer: SystemTime::now(),
                            route_src: route.src,
                            route_changed: true,
                        });
                    }
                    trace!("AFTER routing_table: {:?}", self.routing_table);
                } else {
                    warn!("cost is invalid: {}", route.cost);
                }
            } else {
                trace!("dst: {} is local or global", route.dst);
            }
        }
        self.send_triggered_updates(dl_ctx, source);
    }

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

    fn expire_old_entries(&mut self) {
        for rentry in &mut self.routing_table {
            if rentry.next_hop == rentry.dst {
                rentry.timer = SystemTime::now();
            } else {
                let duration = SystemTime::now().duration_since(rentry.timer).unwrap();
                if duration.as_secs() >= RIP_TIMEOUT {
                    rentry.timer = SystemTime::now();
                    rentry.metric = INFINITY;
                    rentry.route_changed = true;
                }
            }
        }
    }
}

fn build_rip_entry_pkt(rip_ctx: &Arc<RwLock<RipCtx>>, entry_id: usize, packet: &mut [u8]) {
    let mut ripe_pkt = MutableRipEntryPacket::new(packet).unwrap();

    let entry = &(*rip_ctx.read().unwrap()).get_routes()[entry_id];

    ripe_pkt.set_cost(entry.cost as u32);
    ripe_pkt.set_address(entry.dst);
}

fn build_rip_pkt(rip_ctx: &Arc<RwLock<RipCtx>>, packet: &mut [u8], request: bool) -> usize {
    let num_entries = if request {
        let mut rip_pkt = MutableRipPacket::new(packet).unwrap();
        rip_pkt.set_command(1);
        rip_pkt.set_num_entries(0);
        0
    } else {
        let mut rip_pkt = MutableRipPacket::new(packet).unwrap();
        rip_pkt.set_command(2);
        let ne = (*rip_ctx.read().unwrap()).get_num_entries();
        rip_pkt.set_num_entries(ne as u16);
        ne
    };

    let mut idx = 4;
    let mut entry_id = 0;
    while entry_id < num_entries {
        build_rip_entry_pkt(rip_ctx, entry_id, &mut packet[idx..]);
        entry_id += 1;
        idx += 8;
    }

    idx
}

fn send_routing_table(rip_ctx: &Arc<RwLock<RipCtx>>,
                      dl_ctx: &Arc<RwLock<DataLink>>,
                      dst: Ipv4Addr) {
    let mut rip_buf = vec![0u8; RIP_MAX_SIZE];
    let pkt_size = build_rip_pkt(rip_ctx, &mut rip_buf, false);
    let rip_pkt = RipPacket::new(&rip_buf).unwrap();
    let ip_params = ip::IpParams {
        src: Ipv4Addr::new(127, 0, 0, 1),
        dst: dst,
        len: pkt_size,
        tos: 0,
        opt: vec![],
    };
    trace!("SENDING RIP: {:?}", rip_pkt);
    let res = ip::send(dl_ctx,
                       None,
                       None,
                       ip_params,
                       RIP_PROT,
                       INFINITY,
                       rip_pkt.packet().to_vec(),
                       0,
                       true);
    match res {
        Ok(_) => trace!("RIP update sent succesfully on {:?}", dst),
        Err(str) => warn!("{}", str),
    }
}

pub fn start_rip_module(dl_ctx: &Arc<RwLock<DataLink>>, rip_ctx: &Arc<RwLock<RipCtx>>) {
    let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
    for iface in interfaces {
        let mut rip_buf = vec![0u8; 4];
        let pkt_size = build_rip_pkt(rip_ctx, &mut rip_buf, true);
        let rip_pkt = RipPacket::new(&rip_buf).unwrap();
        let ip_params = ip::IpParams {
            src: Ipv4Addr::new(127, 0, 0, 1),
            dst: iface.dst,
            len: pkt_size,
            tos: 0,
            opt: vec![],
        };
        debug!("SENDING RIP REQUEST: {:?}", rip_pkt);
        let res = ip::send(dl_ctx,
                           None,
                           None,
                           ip_params,
                           RIP_PROT,
                           INFINITY,
                           rip_pkt.packet().to_vec(),
                           0,
                           true);
        match res {
            Ok(_) => info!("RIP request sent succesfully on {:?}", iface.dst),
            Err(str) => warn!("{}", str),
        }
    }

    loop {
        (*rip_ctx.write().unwrap()).expire_old_entries();
        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
        for iface in interfaces {
            send_routing_table(rip_ctx, dl_ctx, iface.dst);
        }
        thread::sleep(Duration::from_secs(RIP_PERIOD));
    }
}

pub fn pkt_handler(rip_ctx: &Arc<RwLock<RipCtx>>,
                   dl_ctx: &Arc<RwLock<DataLink>>,
                   rip_pkt: &[u8],
                   ip_params: ip::IpParams) {
    let pkt = RipPacket::new(rip_pkt).unwrap();
    match pkt.get_command() {
        1 => {
            // request
            info!("processing RIP request");
            // TODO check num_entries = 0
            send_routing_table(rip_ctx, dl_ctx, ip_params.src);
        }
        2 => {
            // response
            trace!("processing RIP response");
            if (*dl_ctx.read().unwrap()).is_neighbor_address(ip_params.src) {
                (*rip_ctx.write().unwrap()).update_routing_table(dl_ctx,
                                                                 pkt.get_entries()
                                                                     .iter()
                                                                     .map(|ripentry| {
                        let mut re_buf = vec![0u8; 8];
                        let mut re_pkt = MutableRipEntryPacket::new(&mut re_buf).unwrap();
                        re_pkt.populate(ripentry);
                        Route {
                            dst: re_pkt.get_address(),
                            src: ip_params.src,
                            cost: re_pkt.get_cost() as u8,
                        }
                    })
                                                                     .collect(),
                                                                 Some(ip_params.src));
            } else {
                warn!("RIP packet came from non-neighbor: {}", ip_params.src);
            }
        }
        _ => warn!("Invalid RIP packet, discarding"),
    }
}

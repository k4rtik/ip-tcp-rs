use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{self, MutableIpv4Packet, Ipv4Packet, Ipv4Option};

use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::str;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, RwLock};

use datalink::DataLink;
use rip::{self, RipCtx};

const IPV4_HEADER_LEN: usize = 20;

#[derive(Debug)]
pub struct IpParams {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub len: usize,
    pub tos: u8,
    pub opt: Vec<Ipv4Option>,
}

// This function is mostly a copy of the same function in libpnet benches at:
// https://github.com/libpnet/libpnet/blob/master/benches/rs_sender.rs#L27-L44
fn build_ipv4_header(params: &IpParams, prot: u8, ttl: u8, id: u16, packet: &mut [u8]) {
    let mut ip_header = MutableIpv4Packet::new(packet).unwrap();

    // assuming no options
    let total_len = (IPV4_HEADER_LEN + params.len) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    // TODO set tos here
    ip_header.set_total_length(total_len);
    ip_header.set_identification(id);
    ip_header.set_ttl(ttl);
    ip_header.set_next_level_protocol(IpNextHeaderProtocol(prot));
    ip_header.set_source(params.src);
    ip_header.set_destination(params.dst);
    // if set, total_len needs update with padding
    //  ip_header.set_options(params.opt);

    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

/// conforms to SEND interface described in RFC 791 pg. 32
#[allow(too_many_arguments)]
#[allow(unknown_lints)]
pub fn send(dl_ctx: &Arc<RwLock<DataLink>>,
            rip: Option<&Arc<RwLock<RipCtx>>>,
            params: IpParams,
            prot: u8,
            ttl: u8,
            mut payload: Vec<u8>,
            id: u16,
            df: bool)
            -> Result<(), String> {
    if !df {
        return Err("Fragmentation not supported!".to_string());
    }
    let mut pkt_buf = vec![0u8; IPV4_HEADER_LEN];
    pkt_buf.append(&mut payload);

    match rip {
        Some(rip_ctx) => {
            if (*dl_ctx.read().unwrap()).is_local_address(params.dst) {
                let params = IpParams { src: params.src, ..params };
                build_ipv4_header(&params, prot, ttl, id, &mut pkt_buf);
                let mut pkt = MutableIpv4Packet::new(&mut pkt_buf).unwrap();
                handle_packet(dl_ctx, rip_ctx, &mut pkt);
                Ok(())
            } else {
                match (*rip_ctx.read().unwrap()).get_next_hop(params.dst) {
                    Some(next_hop) => {
                        let params = IpParams {
                            src: if params.src.is_loopback() {
                                match (*dl_ctx.read().unwrap()).get_interface_by_src(next_hop) {
                                    Some(iface) => iface.src,
                                    None => {
                                        return Err("No interface matching next_hop found!"
                                            .to_string())
                                    }
                                }
                            } else {
                                params.src
                            },
                            ..params
                        };
                        trace!{"{:?}", params};
                        build_ipv4_header(&params, prot, ttl, id, &mut pkt_buf);
                        let pkt = MutableIpv4Packet::new(&mut pkt_buf).unwrap();
                        (*dl_ctx.read().unwrap()).send_packet(params.src, pkt.to_immutable())
                    }
                    None => Err("Destination unreachable!".to_string()),
                }
            }
        }
        None => {
            match (*dl_ctx.read().unwrap()).get_interface_by_dst(params.dst) {
                Some(iface) => {
                    let params = IpParams {
                        src: if params.src.is_loopback() {
                            iface.src
                        } else {
                            params.src
                        },
                        ..params
                    };
                    trace!{"{:?}", params};
                    build_ipv4_header(&params, prot, ttl, id, &mut pkt_buf);
                    let pkt = MutableIpv4Packet::new(&mut pkt_buf).unwrap();
                    (*dl_ctx.read().unwrap()).send_packet(params.src, pkt.to_immutable())
                }
                None => Err("No interface matching dst found!".to_string()),
            }
        }
    }
}

/// Any registered handler should conform to RECV interface described in RFC 791 pg. 32
fn handle_packet(dl_ctx: &Arc<RwLock<DataLink>>,
                 rip_ctx: &Arc<RwLock<RipCtx>>,
                 pkt: &mut MutableIpv4Packet) {
    // TODO check for fragmentation
    let dst = pkt.get_destination();
    let iface = (*dl_ctx.read().unwrap()).get_interface_by_src(dst).unwrap();
    if iface.enabled {
        if pkt.get_checksum() == ipv4::checksum(&pkt.to_immutable()) {
            let dst = pkt.get_destination();
            if (*dl_ctx.read().unwrap()).is_local_address(dst) {
                match pkt.get_next_level_protocol() {
                    IpNextHeaderProtocol(0) => {
                        print_pkt_contents(pkt.to_immutable());
                    }
                    IpNextHeaderProtocol(200) => {
                        rip::pkt_handler(rip_ctx,
                                         dl_ctx,
                                         pkt.payload(),
                                         IpParams {
                                             src: pkt.get_source(),
                                             dst: pkt.get_destination(),
                                             len: get_ipv4_payload_length(&pkt.to_immutable()),
                                             tos: 0, // XXX hardcoded, incorrect
                                             opt: pkt.get_options(),
                                         });
                    }
                    _ => warn!("Unsupported packet!"),
                }
            } else {
                // info!("Forwarding to next hop");
                match (*rip_ctx.read().unwrap()).get_next_hop(dst) {
                    Some(hop) => {
                        if pkt.get_ttl() > 0 {
                            let old_ttl = pkt.get_ttl();
                            pkt.set_ttl(old_ttl);
                            let cksum = ipv4::checksum(&pkt.to_immutable());
                            pkt.set_checksum(cksum);
                            (*dl_ctx.read().unwrap())
                                .send_packet(hop, pkt.to_immutable())
                                .unwrap()
                        } else {
                            warn!("TTL reached 0, destroying packet");
                        }
                    }
                    None => warn!("No route to {}", dst),
                }
            }
        } else {
            warn!("Invalid packet, discarding");
        }
    }
}

pub fn start_ip_module(dl_ctx: &Arc<RwLock<DataLink>>,
                       rip_ctx: &Arc<RwLock<RipCtx>>,
                       rx: Receiver<MutableIpv4Packet>) {
    loop {
        let mut pkt = rx.recv().unwrap();
        handle_packet(dl_ctx, rip_ctx, &mut pkt);
    }
}

fn get_ipv4_payload_length(pkt: &Ipv4Packet) -> usize {
    pkt.get_total_length() as usize - pkt.get_header_length() as usize * 4
}

fn print_pkt_contents(pkt: Ipv4Packet) {
    println!("Packet contents:");
    println!("Source IP: {}", pkt.get_source());
    println!("Destination IP: {}", pkt.get_destination());
    let len = get_ipv4_payload_length(&pkt);
    println!("Body length: {}", len);
    println!("Header:");
    println!("\ttos: 0\n\tid: {}\n\tproto: 0", pkt.get_identification());
    let message = Vec::from(&pkt.payload()[..len]);
    println!("Payload: {}", String::from_utf8(message).unwrap());
    print!("> ");
    io::stdout().flush().unwrap();
}

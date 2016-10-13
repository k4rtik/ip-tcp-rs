extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{self, MutableIpv4Packet, Ipv4Packet, Ipv4Option};

use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::sync::mpsc::Receiver;
use std::str;

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
pub fn send(dl_ctx: &Arc<RwLock<DataLink>>,
            rip_ctx: &Arc<RwLock<RipCtx>>,
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
    if (*dl_ctx.read().unwrap()).is_local_address(params.dst) {
        let params = IpParams { src: params.src, ..params };
        build_ipv4_header(&params, prot, ttl, id, &mut pkt_buf);
        let pkt = Ipv4Packet::new(&pkt_buf).unwrap();
        handle_packet(dl_ctx, rip_ctx, pkt);
        Ok(())
    } else {
        let params = IpParams {
            src: if params.src.is_loopback() {
                match (*dl_ctx.read().unwrap()).get_interface_by_dst(params.dst) {
                    Some(iface) => iface.src,
                    None => return Err("No interface matching dst found!".to_string()),
                }
            } else {
                params.src
            },
            ..params
        };
        debug!{"{:?}", params};

        build_ipv4_header(&params, prot, ttl, id, &mut pkt_buf);
        let pkt = Ipv4Packet::new(&pkt_buf).unwrap();
        (*dl_ctx.read().unwrap()).send_packet(params.dst, pkt)
    }
}

/// conforms to RECV interface described in RFC 791 pg. 32
pub fn recv(mut buf: &mut Vec<u8>, prot: u8) -> Result<IpParams, String> {
    Err("Nothing here".to_string())
}

fn handle_packet(dl_ctx: &Arc<RwLock<DataLink>>, rip_ctx: &Arc<RwLock<RipCtx>>, pkt: Ipv4Packet) {
    // TODO check for fragmentation
    if pkt.get_checksum() == ipv4::checksum(&pkt.to_immutable()) {
        let dst = pkt.get_destination();
        if (*dl_ctx.read().unwrap()).is_local_address(dst) {
            match pkt.get_next_level_protocol() {
                IpNextHeaderProtocol(0) => {
                    print_pkt_contents(pkt);
                }
                IpNextHeaderProtocol(200) => {
                    rip::pkt_handler(rip_ctx,
                                     dl_ctx,
                                     pkt.payload(),
                                     IpParams {
                                         src: pkt.get_source(),
                                         dst: pkt.get_destination(),
                                         len: get_ipv4_payload_length(&pkt),
                                         tos: 0, // XXX hardcoded, incorrect
                                         opt: pkt.get_options(),
                                     });
                }
                _ => error!("Unsupported packet!"),
            }
        } else {
            info!("Forwarding to next hop");
            // TODO decrease TTL
            match (*rip_ctx.read().unwrap()).get_next_hop(dst) {
                Some(hop) => (*dl_ctx.read().unwrap()).send_packet(hop, pkt).unwrap(),
                None => error!("No route to {}", dst),
            }
        }
    } else {
        error!("Invalid packet, discarding");
    }
}

pub fn start_ip_module(dl_ctx: &Arc<RwLock<DataLink>>,
                       rip_ctx: &Arc<RwLock<RipCtx>>,
                       rx: Receiver<Ipv4Packet>) {
    loop {
        let pkt = rx.recv().unwrap();
        handle_packet(dl_ctx, rip_ctx, pkt);
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
}

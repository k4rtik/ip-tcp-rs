extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{self, MutableIpv4Packet, Ipv4Packet, Ipv4Option};

use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;

use datalink::DataLink;
use rip;

static IPV4_HEADER_LEN: usize = 20;

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
    // ip_header.set_options(params.opt); // if set, total_len needs update with padding

    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

/// conforms to SEND interface described in RFC 791 pg. 32
pub fn send(datalink: &DataLink,
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
    debug!("{:?}", pkt_buf);

    let params = IpParams {
        src: if params.src.is_loopback() {
            match datalink.get_interface_by_dst(params.dst) {
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
    datalink.send_packet(params.dst, pkt)
}

/// conforms to RECV interface described in RFC 791 pg. 32
pub fn recv(mut buf: &mut Vec<u8>, prot: u8) -> Result<IpParams, String> {
    Err("Nothing here".to_string())
}

fn handle_packet(datalink: &DataLink, pkt: Ipv4Packet) {
    // TODO check for fragmentation
    if pkt.get_checksum() == ipv4::checksum(&pkt.to_immutable()) {
        let dst = pkt.get_destination();
        if datalink.is_local_address(dst) {
            match pkt.get_next_level_protocol() {
                IpNextHeaderProtocol(0) => println!("{:?}", pkt),
                IpNextHeaderProtocol(200) => rip::handler(pkt.payload()),
                _ => info!("Unsupported packet!"),
            }
        } else {
            // TODO decrease TTL
            let next_hop = rip::get_next_hop(dst);
            datalink.send_packet(next_hop, pkt).unwrap();
        }
    } else {
        error!("Invalid packet, discarding");
    }
}

pub fn start_ip_module(datalink: &DataLink, rx: Receiver<Ipv4Packet>) {
    loop {
        let pkt = rx.recv().unwrap();
        handle_packet(datalink, pkt);
    }
}

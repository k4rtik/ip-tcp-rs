extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{self, MutableIpv4Packet, Ipv4Packet};

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;

use datalink::DataLink;
use rip;

static IPV4_HEADER_LEN: usize = 20;
static TTL: u8 = 16;

// This function is mostly a copy of the same function in libpnet benches at:
// https://github.com/libpnet/libpnet/blob/master/benches/rs_sender.rs#L27-L44
fn build_ipv4_header(dst: Ipv4Addr,
                     src: Ipv4Addr,
                     packet: &mut [u8],
                     proto: u8,
                     option_len: usize,
                     payload_len: usize) {
    let mut ip_header = MutableIpv4Packet::new(packet).unwrap();

    let total_len = (IPV4_HEADER_LEN + option_len + payload_len) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(total_len);
    ip_header.set_ttl(TTL);
    ip_header.set_next_level_protocol(IpNextHeaderProtocol(proto));
    ip_header.set_source(src);
    ip_header.set_destination(dst);

    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

pub fn send_message(datalink: &DataLink,
                    dst: Ipv4Addr,
                    mut payload: &mut Vec<u8>,
                    payload_len: usize,
                    proto: u8)
                    -> bool {
    let buf_rc = RefCell::new(vec![0u8; IPV4_HEADER_LEN]);
    {
        let mut buf = buf_rc.borrow_mut();
        buf.append(&mut payload);
        debug!("{:?}", buf);
        let src = match datalink.get_interface_by_dst(dst) {
            Some(iface) => iface.src,
            None => return false,
        };
        build_ipv4_header(dst, src, &mut buf, proto, 0, payload_len);
    }
    let buf = buf_rc.into_inner();
    let pkt = Ipv4Packet::new(&buf).unwrap();
    datalink.send_packet(dst, pkt)
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

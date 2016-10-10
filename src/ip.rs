extern crate pnet;

use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::ip::IpNextHeaderProtocol;
use std::cell::RefCell;
use std::net::Ipv4Addr;

static IPV4_HEADER_LEN: usize = 20;

pub fn build_ipv4_header(dest: Ipv4Addr,
                         packet: &mut [u8],
                         proto: u8,
                         option_len: usize,
                         payload_len: usize) {
    let mut ip_header = MutableIpv4Packet::new(packet).unwrap();

    let total_len = (IPV4_HEADER_LEN + option_len + payload_len) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(total_len);
    ip_header.set_ttl(4);
    ip_header.set_next_level_protocol(IpNextHeaderProtocol(proto));
    ip_header.set_source(Ipv4Addr::new(127, 0, 0, 1));
    ip_header.set_destination(dest);

    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

pub fn send_message(dest: Ipv4Addr,
                    mut payload: &mut Vec<u8>,
                    payload_len: usize,
                    proto: u8)
                    -> RefCell<Vec<u8>> {
    let buf_rc = RefCell::new(vec![0u8; IPV4_HEADER_LEN]);
    {
        let mut buf = buf_rc.borrow_mut();
        buf.append(&mut payload);
        debug!("{:?}", buf);
        build_ipv4_header(dest, &mut buf, proto, 0, payload_len);
    }
    buf_rc
}

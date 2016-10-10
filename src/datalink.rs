use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::sync::mpsc::channel;

pub struct RouteInfo {
    // std::net::UdpSocket accepts string in host:port format
    pub socket_addr: String,
    pub interfaces: Vec<SocketAddrInterface>,
}

#[derive(Debug)]
pub struct SocketAddrInterface {
    pub to_socket_addr: String,
    pub src_vip: Ipv4Addr,
    pub dst_vip: Ipv4Addr,
}

#[derive(Debug)]
pub struct Interface {
    dst: Ipv4Addr,
    src: Ipv4Addr,
    enabled: bool,
}

struct PrivInterface {
    socket_addr: String,
    dst: Ipv4Addr, // also serves as key to this interface
    src: Ipv4Addr,
    enabled: bool,
}

pub struct DataLink {
    local_socket: UdpSocket,
    interfaces: Vec<PrivInterface>,
}

impl DataLink {
    pub fn new(ri: RouteInfo) -> DataLink {
        DataLink {
            local_socket: UdpSocket::bind(&*ri.socket_addr).unwrap(),
            interfaces: ri.interfaces
                .iter()
                .map(|iface| {
                    PrivInterface {
                        socket_addr: iface.to_socket_addr.clone(),
                        dst: iface.dst_vip,
                        src: iface.src_vip,
                        enabled: true,
                    }
                })
                .collect(),
        }
    }

    // called by the IP Layer
    pub fn send_packet(&self, next_hop: Ipv4Addr, pkt: Ipv4Packet) {
        debug!("{:?}, {:?}", next_hop, pkt);
        let socket_addr =
            match (&self.interfaces).into_iter().find(|ref iface| iface.dst == next_hop) {
                Some(ref priv_iface) => priv_iface.socket_addr.clone(),
                None => panic!("Interface doesn't exist!"),
            };
        debug!("{:?}", socket_addr);
        debug!("{:?}", pkt.packet());
        let sent_count = self.local_socket.send_to(pkt.packet(), &*socket_addr);
        debug!("{:?}", sent_count);
    }
}

pub fn activate_interface(id: usize) {}

pub fn deactivate_interface(id: usize) {}

pub fn get_interfaces() {}

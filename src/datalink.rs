use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::net::UdpSocket;

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
    pub dst: Ipv4Addr,
    pub src: Ipv4Addr,
    pub enabled: bool,
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

    // to be called only by the IP Layer
    pub fn send_packet(&self, next_hop: Ipv4Addr, pkt: Ipv4Packet) -> bool {
        debug!("{:?}, {:?}", next_hop, pkt);
        let priv_iface =
            match (&self.interfaces).into_iter().find(|ref iface| iface.dst == next_hop) {
                Some(priv_iface) => priv_iface,
                None => panic!("Interface doesn't exist!"),
            };
        if priv_iface.enabled {
            let socket_addr = priv_iface.socket_addr.clone();
            debug!("{:?}", socket_addr);
            debug!("{:?}", pkt.packet());
            let sent_count = self.local_socket.send_to(pkt.packet(), &*socket_addr);
            debug!("{:?}", sent_count);
            if sent_count.unwrap() > 0 { true } else { false }
        } else {
            info!("interface for {:?} is disabled", next_hop);
            false
        }
    }

    pub fn get_interfaces(&self) -> Vec<Interface> {
        self.interfaces
            .iter()
            .map(|iface| {
                Interface {
                    dst: iface.dst,
                    src: iface.src,
                    enabled: iface.enabled,
                }
            })
            .collect()
    }

    pub fn activate_interface(&mut self, id: usize) -> bool {
        if id > self.interfaces.len() {
            false
        } else {
            if self.interfaces[id].enabled == true {
                println!("interface {} is already enabled!", id);
                true
            } else {
                self.interfaces[id].enabled = true;
                true
            }
        }
    }

    pub fn deactivate_interface(&mut self, id: usize) -> bool {
        if id > self.interfaces.len() {
            false
        } else {
            if self.interfaces[id].enabled == false {
                println!("interface {} is already disabled!", id);
                false
            } else {
                self.interfaces[id].enabled = false;
                true
            }
        }
    }
}

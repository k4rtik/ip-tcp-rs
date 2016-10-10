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
    pub fn send_packet(&self, next_hop: Ipv4Addr, pkt: Ipv4Packet) -> bool {
        debug!("{:?}, {:?}", next_hop, pkt);
	// TODO check if the socker_addr has the interface enabled!
        let socket_addr =
            match (&self.interfaces).into_iter().find(|ref iface| iface.dst == next_hop) {
                Some(ref priv_iface) => priv_iface.socket_addr.clone(),
                None => panic!("Interface doesn't exist!"),
            };
        debug!("{:?}", socket_addr);
        debug!("{:?}", pkt.packet());
        let sent_count = self.local_socket.send_to(pkt.packet(), &*socket_addr);
        debug!("{:?}", sent_count);
        if sent_count.unwrap() > 1 {
            return true;
        } else {
            return false;
        }
    }


    pub fn show_interfaces(&self) {
        // let ret_vec = Vec<Interface>;
        println!("id\tsource\t\tdestination\tstatus");
        let mut idx = 0;
        for i in &self.interfaces {
            println!("{}\t{}\t{}\t{}", idx, i.src, i.dst, i.enabled);
            idx = idx + 1;
        }
    }

    pub fn activate_interface(&mut self, id: usize) -> bool {
        if id > self.interfaces.len() {
            return false;
        } else {
            if self.interfaces[id].enabled == true {
                println!("interface {} is already enabled!", id);
                return true;
            } else {
                self.interfaces[id].enabled = true;
                return true;
            }
        }
    }
    pub fn deactivate_interface(&mut self, id: usize) -> bool {
        if id > self.interfaces.len() {
            return false;
        } else {
            if self.interfaces[id].enabled == false {
                println!("interface {} is already disabled!", id);
                return false;
            } else {
                self.interfaces[id].enabled = false;
                return true;
            }
        }
    }
}

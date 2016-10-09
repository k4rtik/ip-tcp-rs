use pnet::packet::ipv4::Ipv4Packet;
use std::net::UdpSocket;
use std::net::Ipv4Addr;

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
    dst: Ipv4Addr,
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
	
    //called by the IP Layer
    pub fn send_packet(&self, dest_addr: Ipv4Addr, proto: i32, pkt: Ipv4Packet) {
		debug!("{:?}, {:?}, {:?}", dest_addr, proto, pkt);

		//self.local_socket.send_to();
	}
}

pub fn activate_interface(id: usize) {}

pub fn deactivate_interface(id: usize) {}

pub fn get_interfaces() {}


use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;

// TODO choose a better name for this struct
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

#[derive(Debug, Clone)]
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
    pub fn new(ri: &RouteInfo) -> (DataLink, Receiver<Vec<u8>>) {
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
        let socket_addr: Vec<&str> = ri.socket_addr.split(':').collect();
        let host = match socket_addr[0] {
            "localhost" => "127.0.0.1",
            x => x,
        };
        let port: u16 = socket_addr[1].parse().unwrap();
        let dl = DataLink {
            local_socket: UdpSocket::bind((host, port)).unwrap(),
            interfaces: ri.interfaces
                .iter()
                .map(|iface| {
                    PrivInterface {
                        socket_addr: {
                            let socket_addr: Vec<&str> = iface.to_socket_addr.split(':').collect();
                            let host = match socket_addr[0] {
                                "localhost" => "127.0.0.1",
                                x => x,
                            };
                            host.to_string() + ":" + socket_addr[1]
                        },
                        dst: iface.dst_vip,
                        src: iface.src_vip,
                        enabled: true,
                    }
                })
                .collect(),
        };
        dl.start_receiver(tx);
        (dl, rx)
    }

    pub fn get_interface_by_dst(&self, dst: Ipv4Addr) -> Option<Interface> {
        self.get_interfaces()
            .iter()
            .filter_map(|iface| if iface.dst == dst {
                Some((*iface).clone())
            } else {
                None
            })
            .next()
    }

    pub fn get_interface_by_src(&self, src: Ipv4Addr) -> Option<Interface> {
        self.get_interfaces()
            .iter()
            .filter_map(|iface| if iface.src == src {
                Some((*iface).clone())
            } else {
                None
            })
            .next()
    }

    pub fn is_local_address(&self, dst: Ipv4Addr) -> bool {
        self.interfaces.iter().any(|iface| iface.src == dst)
    }

    pub fn is_neighbor_address(&self, dst: Ipv4Addr) -> bool {
        self.interfaces.iter().any(|iface| iface.dst == dst)
    }

    // to be called only by the IP Layer
    pub fn send_packet(&self, next_hop: Ipv4Addr, pkt: Ipv4Packet) -> Result<(), String> {
        trace!("{:?}", next_hop);
        let priv_iface = match (&self.interfaces).into_iter().find(|iface| iface.src == next_hop) {
            Some(priv_iface) => priv_iface,
            None => panic!("Interface doesn't exist!"),
        };
        if priv_iface.enabled {
            let socket_addr = priv_iface.socket_addr.clone();
            let len = pkt.get_total_length() as usize;
            let sent_count = self.local_socket.send_to(&pkt.packet()[..len], &*socket_addr);
            trace!("{:?}", sent_count);
            if sent_count.unwrap() > 0 {
                Ok(())
            } else {
                Err("send_to failed!".to_string())
            }
        } else {
            Err(format!("interface for {:?} is disabled", next_hop))
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
        if id >= self.interfaces.len() {
            println!("interface {} doesn't exist!", id);
            false
        } else if self.interfaces[id].enabled {
            println!("interface {} is already enabled!", id);
            false
        } else {
            self.interfaces[id].enabled = true;
            true
        }
    }

    pub fn deactivate_interface(&mut self, id: usize) -> bool {
        if id >= self.interfaces.len() {
            println!("interface {} doesn't exist!", id);
            false
        } else if self.interfaces[id].enabled {
            self.interfaces[id].enabled = false;
            true
        } else {
            println!("interface {} is already disabled!", id);
            false
        }
    }

    pub fn start_receiver(&self, tx: Sender<Vec<u8>>) {
        let sock = self.local_socket.try_clone().unwrap();
        {
            thread::spawn(move || recv_loop(sock, tx));
        }
    }
}

pub fn recv_loop(sock: UdpSocket, tx: Sender<Vec<u8>>) {
    loop {
        let mut recv_buf = vec![0u8; 65536];
        sock.recv_from(&mut recv_buf).unwrap();
        tx.send(recv_buf).unwrap();
    }
}

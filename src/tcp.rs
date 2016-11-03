use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;

use datalink::DataLink;
use ip;
use rip;

#[derive(Clone, Debug)]
pub enum STATUS {
    Listen,
    SynSent,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug)]
pub struct Socket {
    pub socket_id: usize,
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
    pub status: STATUS,
}

#[derive(Debug)]
struct TCB {
    local_ip: Ipv4Addr,
    local_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    state: STATUS,
}

#[derive(Default)]
pub struct TCP {
    // container of TCBs
    tc_blocks: HashMap<usize, TCB>,
    free_sockets: Vec<usize>,
    bound_ports: HashSet<(Ipv4Addr, u16)>,
}

pub struct TcpParams {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
}

pub fn build_tcp_packet(t_params: TcpParams, payload: &mut [u8]) -> MutableTcpPacket {
    info!("Building TCP packet...");
    let mut tcp_packet = MutableTcpPacket::new(payload).unwrap();
    tcp_packet.set_source(t_params.src_port);
    tcp_packet.set_destination(t_params.dst_port);
    tcp_packet.set_sequence(t_params.seq_num);
    tcp_packet.set_acknowledgement(t_params.ack_num);
    tcp_packet.set_flags(2);
    let cksum = tcp_packet.get_checksum();
    tcp_packet.set_checksum(cksum);
    tcp_packet
}

impl TCP {
    pub fn new() -> TCP {
        debug!("Starting TCP...");
        TCP {
            tc_blocks: HashMap::new(),
            free_sockets: Vec::new(),
            bound_ports: HashSet::new(),
        }
    }

    pub fn get_sockets(&self) -> Vec<Socket> {
        self.tc_blocks
            .iter()
            .map(|(sock, tcb)| {
                Socket {
                    socket_id: *sock,
                    local_addr: tcb.local_ip,
                    local_port: tcb.local_port,
                    dst_addr: tcb.dst_ip,
                    dst_port: tcb.dst_port,
                    status: tcb.state.clone(),
                }
            })
            .collect()
    }

    pub fn v_socket(&mut self) -> Result<usize, String> {
        info!("Creating socket...");
        let sock_id = match self.free_sockets.pop() {
            Some(socket) => socket,
            None => self.tc_blocks.len(),
        };

        let tcb = TCB {
            local_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            local_port: 0,
            dst_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            dst_port: 0,
            state: STATUS::Closed,
        };
        debug!("{:?} {:?} ", sock_id, tcb);

        match self.tc_blocks.insert(sock_id, tcb) {
            Some(v) => {
                warn!("overwrote exisiting value: {:?}", v);
                Ok(sock_id)
            }
            None => Ok(sock_id),
        }
    }

    // TODO if addr is None, bind to any available (local) interface
    pub fn v_bind(&mut self,
                  dl_ctx: &Arc<RwLock<DataLink>>,
                  socket: usize,
                  addr: Option<Ipv4Addr>,
                  port: u16)
                  -> Result<(), String> {
        info!("Binding to IP {:?}, port {}", addr, port);
        match self.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                let ifaces = (*dl_ctx.read().unwrap()).get_interfaces();
                for iface in ifaces {
                    if !self.bound_ports.contains(&(iface.src, port)) {
                        tcb.local_ip = addr.unwrap_or_else(|| iface.src);
                        tcb.local_port = port;
                        self.bound_ports.insert((tcb.local_ip, port));
                        return Ok(());
                    }
                }
                Err("Cannot assign requested address".to_owned())
            }
            None => Err("EBADF: sockfd is not a valid descriptor.".to_owned()),
        }
    }

    pub fn v_listen(&mut self,
                    dl_ctx: &Arc<RwLock<DataLink>>,
                    socket: usize)
                    -> Result<(), String> {
        match self.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                if tcb.local_port != 0 {
                    tcb.state = STATUS::Listen;
                    info!("TCB state changed to LISTEN");
                    Ok(())
                } else {
                    // NOTE we could alternatively query a random port and use if not bound
                    let mut port = 1024;
                    while port != 65535 {
                        let ifaces = (*dl_ctx.read().unwrap()).get_interfaces();
                        for iface in ifaces {
                            if !self.bound_ports.contains(&(iface.src, port)) {
                                debug!("Assigning random port to {}", port);
                                tcb.local_ip = iface.src;
                                tcb.local_port = port;
                                tcb.state = STATUS::Listen;
                                self.bound_ports.insert((tcb.local_ip, port));
                                info!("TCB state changed to LISTEN");
                                return Ok(());
                            }
                        }
                        port += 1;
                    }
                    Err("No available ports to bind!".to_owned())
                }
            }
            None => Err("No TCB associated with this connection!".to_owned()),
        }
    }

    pub fn v_connect(&mut self,
                     dl_ctx: &Arc<RwLock<DataLink>>,
                     socket: usize,
                     addr: Ipv4Addr,
                     port: u16)
                     -> Result<(), String> {
        match self.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                tcb.dst_ip = addr;
                tcb.dst_port = port;
                let t_params = TcpParams {
                    src_port: tcb.local_port,
                    dst_port: tcb.dst_port,
                    seq_num: 0,
                    ack_num: 0,
                };
                let mut pkt_buf = vec![0u8; 20];
                let segment = build_tcp_packet(t_params, &mut pkt_buf);
                // TODO decide on packet size
                let pkt_size = MutableTcpPacket::minimum_packet_size();
                let pkt_sz = 20;
                let ip_params = ip::IpParams {
                    src: Ipv4Addr::new(127, 0, 0, 1),
                    dst: addr,
                    len: pkt_sz,
                    tos: 0,
                    opt: vec![],
                };
                let res = ip::send(dl_ctx,
                                   None,
                                   ip_params,
                                   0, // what should go here?
                                   rip::INFINITY,
                                   segment.packet().to_vec(),
                                   0,
                                   true);
                // tcb.status = STATUS::
                // XXX TODO: Send SYN; change status
                Ok(())
            }
            None => Err("No TCB associated with this connection!".to_owned()),
        }
    }
}

#[allow(unused_variables)]
pub fn v_accept(tcp_ctx: &Arc<RwLock<TCP>>,
                socket: usize,
                addr: Option<Ipv4Addr>)
                -> Result<usize, String> {
    // TODO
    // create new TCB
    // wait for SYN
    // send SYN, ACK
    // switch state to SYN RCVD, need write lock
    // wait for ACK of SYN
    // switch state to ESTAB, need write lock
    thread::sleep(Duration::from_secs(10));
    Ok(0)
}

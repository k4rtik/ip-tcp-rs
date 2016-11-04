use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use pnet_macros_support::types::*;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket, TcpFlags};
use pnet::packet::Packet;
use rand;

use datalink::{DataLink, Interface};
use ip;
use rip::{self, RipCtx};

const TCP_PROT: u8 = 6;

#[derive(Clone, Debug, PartialEq)]
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
    // TODO add more fields pertaining to window size, next_seq, etc
    local_ip: Ipv4Addr,
    local_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    iface: Option<Interface>,
    state: STATUS,
    seq_num: u32,
    next_seq: u32,
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
    flags: u9be,
}

pub fn build_tcp_packet(t_params: TcpParams,
                        src_addr: Ipv4Addr,
                        dst_addr: Ipv4Addr,
                        payload: &mut [u8])
                        -> MutableTcpPacket {
    info!("Building TCP packet...");
    let mut tcp_packet = MutableTcpPacket::new(payload).unwrap();
    tcp_packet.set_source(t_params.src_port);
    tcp_packet.set_destination(t_params.dst_port);
    tcp_packet.set_sequence(t_params.seq_num);
    tcp_packet.set_acknowledgement(t_params.ack_num);
    tcp_packet.set_flags(t_params.flags);
    let cksum = ipv4_checksum(&tcp_packet.to_immutable(), src_addr, dst_addr);
    tcp_packet.set_checksum(cksum);
    debug!("TCP packet: {:?}", tcp_packet);
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
            iface: None,
            state: STATUS::Closed,
            seq_num: 0,
            next_seq: 0,
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

    fn get_unused_ip_port(&self, dl_ctx: &Arc<RwLock<DataLink>>) -> Option<(Ipv4Addr, u16)> {
        let ifaces = (*dl_ctx.read().unwrap()).get_interfaces();
        for port in 1024..65535 {
            for iface in &ifaces {
                if !self.bound_ports.contains(&(iface.src, port)) {
                    return Some((iface.src, port));
                }
            }
        }
        None
    }

    pub fn v_listen(&mut self,
                    dl_ctx: &Arc<RwLock<DataLink>>,
                    socket: usize)
                    -> Result<(), String> {
        let ip_port = self.get_unused_ip_port(dl_ctx).unwrap();
        match self.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                if tcb.local_port != 0 {
                    tcb.state = STATUS::Listen;
                    info!("TCB state changed to LISTEN");
                    Ok(())
                } else {
                    tcb.local_ip = ip_port.0;
                    tcb.local_port = ip_port.1;
                    tcb.state = STATUS::Listen;
                    self.bound_ports.insert((tcb.local_ip, tcb.local_port));
                    info!("TCB state changed to LISTEN");
                    Ok(())
                }
            }
            None => Err("No TCB associated with this connection!".to_owned()),
        }
    }

    pub fn v_connect(&mut self,
                     dl_ctx: &Arc<RwLock<DataLink>>,
                     rip_ctx: &Arc<RwLock<RipCtx>>,
                     socket: usize,
                     dst_addr: Ipv4Addr,
                     port: u16)
                     -> Result<(), String> {
        // send SYN
        let unused_port = self.get_unused_ip_port(dl_ctx).unwrap().1;
        match self.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                if tcb.state == STATUS::Closed {
                    tcb.dst_ip = dst_addr;
                    tcb.dst_port = port;
                    tcb.local_ip = (*rip_ctx.read().unwrap()).get_next_hop(dst_addr).unwrap();
                    tcb.local_port = unused_port;
                    tcb.seq_num = rand::random::<u32>();
                    self.bound_ports.insert((tcb.local_ip, tcb.local_port));
                    let t_params = TcpParams {
                        src_port: tcb.local_port,
                        dst_port: tcb.dst_port,
                        seq_num: tcb.seq_num,
                        ack_num: 0,
                        flags: TcpFlags::SYN,
                    };
                    let mut pkt_buf = vec![0u8; 20];
                    let segment = build_tcp_packet(t_params, tcb.local_ip, dst_addr, &mut pkt_buf);
                    let pkt_sz = MutableTcpPacket::minimum_packet_size();
                    let ip_params = ip::IpParams {
                        src: Ipv4Addr::new(127, 0, 0, 1),
                        dst: dst_addr,
                        len: pkt_sz,
                        tos: 0,
                        opt: vec![],
                    };
                    ip::send(dl_ctx,
                             Some(rip_ctx),
                             None,
                             ip_params,
                             TCP_PROT,
                             rip::INFINITY,
                             segment.packet().to_vec(),
                             0,
                             true)
                        .unwrap();
                    tcb.state = STATUS::SynSent;
                    Ok(())
                } else {
                    Err(format!("EISCONN/EALREADY: TCB not in CLOSED state: {:?}", tcb))
                }
            }
            None => Err("ENOTSOCK: No TCB associated with this connection!".to_owned()),
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

pub fn pkt_handler(dl_ctx: &Arc<RwLock<DataLink>>,
                   rip_ctx: &Arc<RwLock<RipCtx>>,
                   tcp_ctx: &Arc<RwLock<TCP>>,
                   tcp_pkt: &[u8],
                   ip_params: ip::IpParams) {
    let pkt = TcpPacket::new(tcp_pkt).unwrap();
    debug!("{:?}", pkt);

    // TODO verify checksum
    let seq_num = pkt.get_sequence();

    let (lip, lp, dip, dp) =
        (ip_params.dst, pkt.get_destination(), ip_params.src, pkt.get_source());

    for (_, tcb) in &mut (*tcp_ctx.write().unwrap()).tc_blocks {
        if tcb.local_ip == lip && tcb.local_port == lp && tcb.dst_ip == dip && tcb.dst_port == dp {

            if tcb.state == STATUS::SynSent {
                tcb.next_seq = seq_num + 1;
                let t_params = TcpParams {
                    src_port: tcb.local_port,
                    dst_port: tcb.dst_port,
                    seq_num: tcb.seq_num,
                    ack_num: tcb.next_seq,
                    flags: TcpFlags::ACK,
                };
                let mut pkt_buf = vec![0u8; 20];
                let segment = build_tcp_packet(t_params, lip, dip, &mut pkt_buf);
                let pkt_sz = MutableTcpPacket::minimum_packet_size();
                let ip_params = ip::IpParams {
                    src: Ipv4Addr::new(127, 0, 0, 1),
                    dst: dip,
                    len: pkt_sz,
                    tos: 0,
                    opt: vec![],
                };
                ip::send(dl_ctx,
                         Some(rip_ctx),
                         None,
                         ip_params,
                         TCP_PROT,
                         rip::INFINITY,
                         segment.packet().to_vec(),
                         0,
                         true)
                    .unwrap();
                tcb.state = STATUS::Estab;
            } else {
                warn!("TCB not in SYN_SENT state: {:?}", tcb);
            }
            break;
        }
    }
}

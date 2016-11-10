use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use pnet_macros_support::types::*;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::packet::FromPacket;
use rand;

use datalink::DataLink;
use ip;
use rip::{self, RipCtx};

const TCP_PROT: u8 = 6;
const MSS: usize = 1480; // 1500 (MTU) - IPV4_HEADER_LEN
const TCP_MAX_WINDOW_SZ: usize = 65536;

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
    state: STATUS,
    seq_num: u32,
    next_seq: u32,
    conn_socks: Vec<usize>,

    window_sz: u16,
    s_window: Vec<u8>,
    r_window: Vec<u8>,
    snd_unackd: u32,
    snd_nxt: u32,
    snd_ackd: u32,
    recv_nxt: u32,
    recv_ackd: u32,
    recv_rd: u32,
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
    window: u16be,
}

pub fn build_tcp_header(t_params: TcpParams,
                        src_addr: Ipv4Addr,
                        dst_addr: Ipv4Addr,
                        payload: Option<&[u8]>,
                        buff: &mut [u8]) {
    info!("Building TCP packet...");
    let mut tcp_packet = MutableTcpPacket::new(buff).unwrap();
    tcp_packet.set_source(t_params.src_port);
    tcp_packet.set_destination(t_params.dst_port);
    tcp_packet.set_sequence(t_params.seq_num);
    tcp_packet.set_acknowledgement(t_params.ack_num);
    tcp_packet.set_data_offset((TcpPacket::minimum_packet_size() / 4) as u4); // number of 32-bit words in header
    tcp_packet.set_flags(t_params.flags);
    tcp_packet.set_window(t_params.window);
    if let Some(payload) = payload {
        tcp_packet.set_payload(payload)
    }
    let cksum = ipv4_checksum(&tcp_packet.to_immutable(), src_addr, dst_addr);
    tcp_packet.set_checksum(cksum);
}

impl TCP {
    pub fn new() -> TCP {
        info!("Starting TCP...");
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
            seq_num: 0,
            next_seq: 0,
            conn_socks: Vec::new(),
            window_sz: TCP_MAX_WINDOW_SZ as u16,
            s_window: vec![0u8; TCP_MAX_WINDOW_SZ],
            r_window: vec![0u8; TCP_MAX_WINDOW_SZ],
            snd_unackd: 0,
            snd_nxt: 0,
            snd_ackd: 0,
            recv_nxt: 0,
            recv_ackd: 0,
            recv_rd: 0,
        };

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
                        window: tcb.window_sz as u16be,
                    };
                    let mut pkt_buf = vec![0u8; 20];
                    build_tcp_header(t_params, tcb.local_ip, dst_addr, None, &mut pkt_buf);
                    let segment = TcpPacket::new(&pkt_buf).unwrap();
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


pub fn v_write(tcp_ctx: &Arc<RwLock<TCP>>,
               dl_ctx: &Arc<RwLock<DataLink>>,
               rip_ctx: &Arc<RwLock<RipCtx>>,
               socket: usize,
               message: &[u8])
               -> Result<usize, String> {
    let tcp = &mut *tcp_ctx.write().unwrap();
    match tcp.tc_blocks.get_mut(&socket) {
        Some(tcb) => {
            let sz = message.len();
            let t_params = TcpParams {
                src_port: tcb.local_port,
                dst_port: tcb.dst_port,
                seq_num: tcb.seq_num,
                ack_num: tcb.next_seq,
                flags: TcpFlags::ACK,
                window: tcb.window_sz as u16be,
            };
            let mut buff = vec![0u8; TcpPacket::minimum_packet_size() + message.len()];
            build_tcp_header(t_params, tcb.local_ip, tcb.dst_ip, Some(message), &mut buff);
            let segment = MutableTcpPacket::new(&mut buff).unwrap();
            debug!("payload: {:?}", segment.payload());
            let pkt_sz = MutableTcpPacket::packet_size(&segment.from_packet());
            let ip_params = ip::IpParams {
                src: tcb.local_ip,
                dst: tcb.dst_ip,
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
            Ok(sz)
        }
        None => Err("Error: No connection setup!".to_owned()),
    }
}
pub fn pkt_handler(dl_ctx: &Arc<RwLock<DataLink>>,
                   rip_ctx: &Arc<RwLock<RipCtx>>,
                   tcp_ctx: &Arc<RwLock<TCP>>,
                   tcp_pkt: &[u8],
                   ip_params: ip::IpParams) {
    let pkt = TcpPacket::new(tcp_pkt).unwrap();
    debug!("{:?}", pkt);

    // TODO verify checksum
    let other_seq_num = pkt.get_sequence();
    let flags = pkt.get_flags();
    let window = pkt.get_window();

    let (lip, lp, dip, dp) =
        (ip_params.dst, pkt.get_destination(), ip_params.src, pkt.get_source());

    let unused_port = (*tcp_ctx.read().unwrap()).get_unused_ip_port(dl_ctx).unwrap().1;
    let tcp = &mut *tcp_ctx.write().unwrap();

    let mut need_new_tcb = false;
    let mut need_estab = false;
    let mut child_socks = Vec::new();
    let mut parent_tcb_sock = 65535;
    let mut ntcb = TCB {
        local_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
        local_port: 0,
        dst_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
        dst_port: 0,
        state: STATUS::Closed,
        seq_num: 0,
        next_seq: 0,
        conn_socks: Vec::new(),
        window_sz: TCP_MAX_WINDOW_SZ as u16,
        s_window: vec![0u8; TCP_MAX_WINDOW_SZ],
        r_window: vec![0u8; TCP_MAX_WINDOW_SZ],
        snd_unackd: 0,
        snd_nxt: 0,
        snd_ackd: 0,
        recv_nxt: 0,
        recv_ackd: 0,
        recv_rd: 0,
    };

    for (sock, tcb) in &mut tcp.tc_blocks {
        // regular socket
        if tcb.local_ip == lip && tcb.local_port == lp && tcb.dst_ip == dip && tcb.dst_port == dp {
            if tcb.state == STATUS::SynSent {
                tcb.next_seq = other_seq_num + 1; // next expected seq / ack
                tcb.snd_unackd = tcb.seq_num + 1;
                tcb.window_sz = window;
                let t_params = TcpParams {
                    src_port: tcb.local_port,
                    dst_port: tcb.dst_port,
                    seq_num: tcb.snd_unackd,
                    ack_num: tcb.next_seq,
                    flags: TcpFlags::ACK,
                    window: window,
                };
                let pkt_sz = MutableTcpPacket::minimum_packet_size();
                let mut pkt_buf = vec![0u8; pkt_sz];
                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                let segment = TcpPacket::new(&pkt_buf[..]).unwrap();
                let ip_params = ip::IpParams {
                    src: lip,
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
                tcb.seq_num = tcb.snd_unackd;
            } else {
                warn!("TCB not in SYN_SENT state: {:?}", tcb);
            }
            break;
        }

        // listening socket
        if tcb.local_ip == lip && tcb.local_port == lp {
            // new connection
            if tcb.state == STATUS::Listen && flags == TcpFlags::SYN {
                ntcb.local_ip = tcb.local_ip;
                ntcb.local_port = unused_port;
                ntcb.dst_ip = dip;
                ntcb.dst_port = dp;
                ntcb.state = STATUS::SynRcvd;
                ntcb.seq_num = rand::random::<u32>();
                ntcb.next_seq = other_seq_num + 1;
                ntcb.window_sz = window;

                parent_tcb_sock = *sock;
                need_new_tcb = true;

                tcp.bound_ports.insert((ntcb.local_ip, ntcb.local_port));

                let t_params = TcpParams {
                    src_port: tcb.local_port,
                    dst_port: ntcb.dst_port,
                    seq_num: ntcb.seq_num,
                    ack_num: ntcb.next_seq,
                    flags: TcpFlags::SYN | TcpFlags::ACK,
                    window: ntcb.window_sz as u16be,
                };
                let pkt_sz = MutableTcpPacket::minimum_packet_size();
                let mut pkt_buf = vec![0u8; pkt_sz];
                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                let segment = TcpPacket::new(&pkt_buf[..]).unwrap();
                let ip_params = ip::IpParams {
                    src: lip,
                    dst: dip,
                    len: pkt_sz,
                    tos: 0,
                    opt: vec![],
                };
                debug!("{:?}", segment);
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
            } else {
                // existing connection
                need_estab = true;
                child_socks = tcb.conn_socks.clone();
            }
            break;
        }
    }

    if need_new_tcb {
        let sock_id = match tcp.free_sockets.pop() {
            Some(socket) => socket,
            None => tcp.tc_blocks.len(),
        };

        tcp.tc_blocks.get_mut(&parent_tcb_sock).unwrap().conn_socks.push(sock_id);

        info!("v_accept returned: {}", sock_id);
        tcp.tc_blocks.insert(sock_id, ntcb);
    } else if need_estab {
        for child_sock in &child_socks {
            let child_tcb = tcp.tc_blocks.get_mut(child_sock).unwrap();
            if child_tcb.dst_ip == dip && child_tcb.dst_port == dp {
                child_tcb.state = STATUS::Estab;
            }
        }
    }
}

use std::collections::{HashMap, HashSet};
use std::collections::vec_deque::VecDeque;
use std::sync::{Arc, RwLock, Mutex};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use std::str;
use std::sync::mpsc::{self, Sender, Receiver};

use pnet_macros_support::types::*;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::packet::FromPacket;
use rand;

use datalink::DataLink;
use ip;
use rip::{self, RipCtx};

const TCP_PROT: u8 = 6;
const TCP_MAX_WINDOW_SZ: usize = 65535;

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


#[derive(Clone, Debug, PartialEq)]
pub enum CMD {
    UserCall,
    Timeout,
    IpRecv,
}

pub struct TCPpkt_IPparams {
    pub pkt: MutableTcpPacket<'static>,
    pub params: ip::IpParams,
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
    remote_ip: Ipv4Addr,
    remote_port: u16,
    state: STATUS,

    snd_buffer: Vec<u8>, // user's send buffer
    rcv_buffer: Vec<u8>, // user's receive buffer
    cur_segment: Option<TcpPacket<'static>>, // current segment
    retransmit_q: VecDeque<TcpPacket<'static>>, // retransmit queue, TODO ipParams needed?

    // Send Sequence Variables
    snd_una: u32, // send unacknowledged
    snd_nxt: u32, // send next
    snd_wnd: u16, // send window (size)
    snd_wl1: u32, // segment sequence number used for last window update
    snd_wl2: u32, // segment acknowledgement number used for last window update
    iss: u32, // initial send sequence number

    // Receive Sequence Variables
    rcv_nxt: u32, // receive next
    rcv_wnd: u16, // receive window (size)
    irs: u32, // initial receive sequence number
    read_nxt: u32,

    // only for LISTEN
    conns_q: VecDeque<TCB>,
    s_chann: Arc<Mutex<Sender<TCPpkt_IPparams>>>,
    r_chann: Arc<Mutex<Receiver<TCPpkt_IPparams>>>,
}

impl TCB {
    fn new() -> TCB {
        let (tx, rx): (Sender<TCPpkt_IPparams>, Receiver<TCPpkt_IPparams>) = mpsc::channel();
        TCB {
            local_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            local_port: 0,
            remote_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            remote_port: 0,
            state: STATUS::Closed,

            snd_buffer: Vec::new(),
            rcv_buffer: Vec::new(),
            cur_segment: None,
            retransmit_q: VecDeque::new(),

            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: TCP_MAX_WINDOW_SZ as u16,
            snd_wl1: 0,
            snd_wl2: 0,
            iss: rand::random::<u16>() as u32,

            rcv_nxt: 0,
            rcv_wnd: TCP_MAX_WINDOW_SZ as u16,
            irs: rand::random::<u16>() as u32,
            read_nxt: 0,

            conns_q: VecDeque::new(),
            s_chann: Arc::new(Mutex::new(tx)),
            r_chann: Arc::new(Mutex::new(rx)),
        }
    }
}

#[derive(Default)]
pub struct TCP {
    // container of TCBs
    tc_blocks: HashMap<usize, TCB>,
    free_sockets: Vec<usize>,
    bound_ports: HashSet<(Ipv4Addr, u16)>,
    fourtup_to_sock: HashMap<FourTup, usize>,
}

#[derive(Hash, PartialEq, Eq)]
pub struct FourTup {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
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
    trace!("Building TCP packet...");
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
            fourtup_to_sock: HashMap::new(),
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
                    dst_addr: tcb.remote_ip,
                    dst_port: tcb.remote_port,
                    status: tcb.state.clone(),
                }
            })
            .collect()
    }

    pub fn v_socket(&mut self) -> Result<usize, String> {
        trace!("Creating socket...");
        let sock_id = match self.free_sockets.pop() {
            Some(socket) => socket,
            None => self.tc_blocks.len(),
        };

        let tcb = TCB::new();

        match self.tc_blocks.insert(sock_id, tcb) {
            Some(v) => {
                warn!("overwrote exisiting value: {:?}", v);
                Ok(sock_id)
            }
            None => Ok(sock_id),
        }
    }

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
                        // remote ip and port are zeros from v_socket()
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
        for iface in &ifaces {
            for port in 1024..65535 {
                if !self.bound_ports.contains(&(iface.src, port)) {
                    debug!("Bound ports: {:?}", self.bound_ports);
                    debug!("Returning: {:?} {:?}", iface.src, port);
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
                if tcb.local_port == 0 {
                    tcb.local_ip = ip_port.0;
                    tcb.local_port = ip_port.1;
                    self.bound_ports.insert((tcb.local_ip, tcb.local_port));
                }
                tcb.state = STATUS::Listen;
                info!("TCB state changed to LISTEN");
                Ok(())
            }
            None => Err("No TCB associated with this connection!".to_owned()),
        }
    }
}

pub fn v_connect(tcp_ctx: &Arc<RwLock<TCP>>,
                 dl_ctx: &Arc<RwLock<DataLink>>,
                 rip_ctx: &Arc<RwLock<RipCtx>>,
                 socket: usize,
                 dst_addr: Ipv4Addr,
                 port: u16)
                 -> Result<(), String> {
    let local_ip = (*rip_ctx.read().unwrap()).get_next_hop(dst_addr).unwrap();
    let mut unused_port: u16 = 0;
    for port in 1024..65535 {
        if !(*tcp_ctx.read().unwrap()).bound_ports.contains(&(local_ip, port)) {
            unused_port = port;
            break;
        }
    }

    if unused_port == 0 {
        return Err("Ran out of free ports!".to_owned());
    }

    let t_params: TcpParams;
    let ip_params: ip::IpParams;
    let mut pkt_buf = vec![0u8; 20];
    if let Some(tcb) = (*tcp_ctx.write().unwrap()).tc_blocks.get_mut(&socket) {
        if tcb.state == STATUS::Closed {
            tcb.local_ip = local_ip;
            tcb.local_port = unused_port;
            tcb.remote_ip = dst_addr;
            tcb.remote_port = port;

            t_params = TcpParams {
                src_port: tcb.local_port,
                dst_port: tcb.remote_port,
                seq_num: tcb.iss,
                ack_num: 0,
                flags: TcpFlags::SYN,
                window: tcb.rcv_wnd,
            };

            build_tcp_header(t_params, tcb.local_ip, dst_addr, None, &mut pkt_buf);
            let pkt_sz = MutableTcpPacket::minimum_packet_size();
            ip_params = ip::IpParams {
                src: local_ip,
                dst: dst_addr,
                len: pkt_sz,
                tos: 0,
                opt: vec![],
            };

            tcb.snd_una = tcb.iss;
            tcb.snd_nxt = tcb.iss + 1;
            tcb.state = STATUS::SynSent;
        } else {
            return Err(format!("EISCONN/EALREADY: TCB not in CLOSED state: {:?}", tcb));
        }
    } else {
        return Err("ENOTSOCK: No TCB associated with this connection!".to_owned());
    }

    (*tcp_ctx.write().unwrap()).bound_ports.insert((local_ip, unused_port));
    // send SYN
    let segment = TcpPacket::new(&pkt_buf).unwrap();
    ip::send(dl_ctx,
             Some(rip_ctx),
             Some(tcp_ctx),
             ip_params,
             TCP_PROT,
             rip::INFINITY,
             segment.packet().to_vec(),
             0,
             true)
        .unwrap();

    // TODO put in retransmit_q?

    Ok(())
}

#[allow(unused_variables)]
pub fn v_accept(tcp_ctx: &Arc<RwLock<TCP>>,
                socket: usize,
                addr: Option<Ipv4Addr>)
                -> Result<usize, String> {
    thread::sleep(Duration::from_secs(100));
    Ok(0)
}

pub fn v_read(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, size: usize, block: bool) -> usize {
    let tcp = &mut *tcp_ctx.write().unwrap();
    match tcp.tc_blocks.get_mut(&socket) {
        Some(tcb) => {
            if (tcb.read_nxt + tcb.irs + size as u32) < tcb.rcv_nxt {
                let i = tcb.read_nxt as usize;
                println!("payload: {}",
                         String::from_utf8_lossy(&tcb.rcv_buffer[i..i + size]));
                tcb.read_nxt += size as u32;
                size
            } else if !block {
                warn!("not enough bytes in recv buffer");
                0
            } else {
                0
            }
        }
        None => 0,
    }
}

pub fn v_write(tcp_ctx: &Arc<RwLock<TCP>>,
               dl_ctx: &Arc<RwLock<DataLink>>,
               rip_ctx: &Arc<RwLock<RipCtx>>,
               socket: usize,
               message: &[u8])
               -> Result<usize, String> {
    let t_params: TcpParams;
    let mut pkt_buf: Vec<u8>;
    let segment: MutableTcpPacket;
    let ip_params: ip::IpParams;

    {
        let tcp = &mut *tcp_ctx.write().unwrap();
        match tcp.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                if tcb.snd_wnd > ((tcb.snd_nxt - tcb.iss + message.len() as u32) as u16) {
                    t_params = TcpParams {
                        src_port: tcb.local_port,
                        dst_port: tcb.remote_port,
                        seq_num: tcb.snd_nxt,
                        ack_num: tcb.rcv_nxt,
                        flags: TcpFlags::ACK,
                        window: tcb.rcv_wnd,
                    };
                    pkt_buf = vec![0u8; TcpPacket::minimum_packet_size() + message.len()];
                    build_tcp_header(t_params,
                                     tcb.local_ip,
                                     tcb.remote_ip,
                                     Some(message),
                                     &mut pkt_buf);
                    segment = MutableTcpPacket::new(&mut pkt_buf).unwrap();
                    let pkt_sz = MutableTcpPacket::packet_size(&segment.from_packet());
                    ip_params = ip::IpParams {
                        src: tcb.local_ip,
                        dst: tcb.remote_ip,
                        len: pkt_sz,
                        tos: 0,
                        opt: vec![],
                    };
                    tcb.snd_nxt += message.len() as u32;
                    tcb.snd_wnd -= message.len() as u16;
                    ip::send(dl_ctx,
                             Some(rip_ctx),
                             Some(tcp_ctx),
                             ip_params,
                             TCP_PROT,
                             rip::INFINITY,
                             segment.packet().to_vec(),
                             0,
                             true)
                        .unwrap();
                } else {
                    warn!("No place in the send window!");
                }
            }
            None => {
                return Err("Error: No connection setup!".to_owned());
            }
        }
    }
    Ok(message.len())
}


pub fn demux(tcp_ctx: &Arc<RwLock<TCP>>,
             bytes: &[u8],
             cmd: CMD,
             ip_params: Option<ip::IpParams>)
             -> Result<(), String> {
    let tcp = &mut *tcp_ctx.write().unwrap();
    match cmd {
        CMD::IpRecv => {
            let ip_params = ip_params.unwrap();
            let tcp_pkt = TcpPacket::new(bytes).unwrap();
            let four_tup = FourTup {
                src_ip: ip_params.src,
                src_port: tcp_pkt.get_source(),
                dst_ip: ip_params.dst,
                dst_port: tcp_pkt.get_destination(),
            };
            match tcp.fourtup_to_sock.get(&four_tup) {
                Some(sock) => {
                    match tcp.tc_blocks.get(&sock) {
                        Some(tcb) => {
                            // *(tcb.s_chann.write().unwrap()).send(tcp_pkt);
                            Ok(())
                        }
                        None => Err("No matching TCB found!".to_owned()),
                    }
                }
                None => Err("No corresponding socket found!".to_owned()),
            }
        }
        CMD::UserCall => Ok(()),

        _ => Err("Unrecognized command!".to_owned()),
    }
}

pub fn pkt_handler(dl_ctx: &Arc<RwLock<DataLink>>,
                   rip_ctx: &Arc<RwLock<RipCtx>>,
                   tcp_ctx: &Arc<RwLock<TCP>>,
                   tcp_pkt: &[u8],
                   ip_params: ip::IpParams) {
    let pkt = TcpPacket::new(tcp_pkt).unwrap();
    trace!("{:?}", pkt);
    // TODO verify checksum
    let pkt_seq_num = pkt.get_sequence();
    let pkt_ack = pkt.get_acknowledgement();
    let pkt_flags = pkt.get_flags();
    let pkt_window = pkt.get_window();

    let pkt_size = ip_params.len;

    let (lip, lp, dip, dp) =
        (ip_params.dst, pkt.get_destination(), ip_params.src, pkt.get_source());

    let mut found_match = false;

    let mut need_new_tcb = false;
    let mut should_send_packet = false;
    let mut parent_socket = 0;

    let mut mark_tcb_for_deletion = false;
    let mut sock_to_be_deleted = 0;

    let mut t_params: TcpParams;
    let pkt_sz = MutableTcpPacket::minimum_packet_size();
    let ip_params = ip::IpParams {
        src: lip,
        dst: dip,
        len: pkt_sz,
        tos: 0,
        opt: vec![],
    };
    let mut pkt_buf = vec![0u8; pkt_sz];

    {
        let tcp = &mut *tcp_ctx.write().unwrap();
        for (sock, tcb) in &mut tcp.tc_blocks {
            // regular socket
            if tcb.local_ip == lip && tcb.local_port == lp && tcb.remote_ip == dip &&
               tcb.remote_port == dp {
                found_match = true;
                debug!("found matching socket");
                tcb.snd_wnd = pkt_window;
                trace!("snd_wnd = {:?}", tcb.snd_wnd);
                match tcb.state {
                    STATUS::Closed => {
                        // Pg. 65 in RFC 793
                        info!("packet recvd on Closed TCB");
                        break; // discard segment, return
                    }
                    STATUS::Listen => {
                        // Pg. 65-66 in RFC 793
                        info!("packet recvd on TCB in Listen State");
                        break; // discard segment, return
                    }
                    STATUS::SynSent => {
                        if pkt_flags & TcpFlags::ACK == TcpFlags::ACK {
                            // Pg. 66 in RFC 793
                            if pkt_ack <= tcb.iss || pkt_ack > tcb.snd_nxt {
                                break; // discard segment, return
                            } else if tcb.snd_una <= pkt_ack && pkt_ack < tcb.snd_nxt {
                                info!("acceptable ACK");
                            }
                        }
                        if pkt_flags & TcpFlags::SYN == TcpFlags::SYN {
                            // Pg. 68 in RFC 793
                            // this is presumably SYN+ACK
                            tcb.rcv_nxt = pkt_seq_num + 1;
                            tcb.irs = pkt_seq_num;
                            tcb.snd_una = pkt_ack;
                            // TODO discard ack'ed segments from retransmit_q
                            if tcb.snd_una > tcb.iss {
                                tcb.state = STATUS::Estab;
                                println!("v_connect() returned 0");

                                t_params = TcpParams {
                                    src_port: tcb.local_port,
                                    dst_port: tcb.remote_port,
                                    seq_num: tcb.snd_nxt,
                                    ack_num: tcb.rcv_nxt,
                                    flags: TcpFlags::ACK,
                                    window: tcb.rcv_wnd,
                                };
                                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                                should_send_packet = true;
                            } else {
                                tcb.state = STATUS::SynRcvd;
                                println!("switching from SynSent to SynRcvd");

                                t_params = TcpParams {
                                    src_port: tcb.local_port,
                                    dst_port: tcb.remote_port,
                                    seq_num: tcb.snd_nxt,
                                    ack_num: tcb.rcv_nxt,
                                    flags: TcpFlags::SYN | TcpFlags::ACK,
                                    window: tcb.rcv_wnd,
                                };
                                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                                should_send_packet = true;
                            }
                        } else {
                            break; // discard segment, return
                        }
                    }
                    _ => {
                        // Otherwise, pg. 69 in RFC 793
                        // TODO discard old dups
                        let seg_len = pkt_size as u32 - 20;
                        debug!("incoming segment length: {}", seg_len);
                        if tcb.rcv_wnd == 0 {
                            if seg_len > 0 {
                                warn!("Dropping packet, cannot accept with 0 window, sending ACK...");
                                t_params = TcpParams {
                                    src_port: tcb.local_port,
                                    dst_port: tcb.remote_port,
                                    seq_num: tcb.snd_nxt,
                                    ack_num: tcb.rcv_nxt,
                                    flags: TcpFlags::ACK,
                                    window: tcb.rcv_wnd,
                                };
                                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                                should_send_packet = true;
                                break;
                            } else if seg_len == 0 && pkt_seq_num == tcb.rcv_nxt {
                                info!("received packet is probably an ACK");
                            } else {
                                warn!("Dropping packet, looks invalid, sending ACK...");
                                t_params = TcpParams {
                                    src_port: tcb.local_port,
                                    dst_port: tcb.remote_port,
                                    seq_num: tcb.snd_nxt,
                                    ack_num: tcb.rcv_nxt,
                                    flags: TcpFlags::ACK,
                                    window: tcb.rcv_wnd,
                                };
                                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                                should_send_packet = true;
                                break;
                            }
                        } else {
                            // tcb.rcv_wnd > 0
                            if seg_len == 0 && tcb.rcv_nxt <= pkt_seq_num &&
                               pkt_seq_num < tcb.rcv_nxt + tcb.rcv_wnd as u32 {
                                info!("received packet is probably an ACK");
                            } else if seg_len > 0 &&
                                      (tcb.rcv_nxt <= pkt_seq_num &&
                                       pkt_seq_num < tcb.rcv_nxt + tcb.rcv_wnd as u32 ||
                                       tcb.rcv_nxt <= pkt_seq_num + seg_len - 1 &&
                                       pkt_seq_num + seg_len - 1 <
                                       tcb.rcv_nxt + tcb.rcv_wnd as u32) {
                                if tcb.rcv_nxt == pkt_seq_num {
                                    // ideal case
                                    if pkt_flags & TcpFlags::SYN == TcpFlags::SYN {
                                        // Pg. 71 in RFC 793
                                        warn!("received SYN in the window, discarding TCB");
                                        println!("connection reset");
                                        tcb.state = STATUS::Closed;
                                        mark_tcb_for_deletion = true;
                                        sock_to_be_deleted = *sock;
                                        break;
                                    }

                                    if pkt_flags & TcpFlags::ACK == TcpFlags::ACK {
                                        match tcb.state {
                                            STATUS::SynRcvd => {
                                                // Pg. 72 in RFC 793
                                                if tcb.snd_una <= pkt_ack &&
                                                   pkt_ack <= tcb.snd_nxt {
                                                    tcb.state = STATUS::Estab;
                                                    println!("v_connect() returned 0");
                                                }
                                            }
                                            STATUS::Estab | STATUS::FinWait1 |
                                            STATUS::FinWait2 | STATUS::CloseWait |
                                            STATUS::Closing => {
                                                if tcb.snd_una < pkt_ack && pkt_ack <= tcb.snd_nxt {
                                                    tcb.snd_una = pkt_ack;
                                                    // TODO discard old segments from retransmit_q
                                                    // and inform user of success of v_write()

                                                    // update send window
                                                    if tcb.snd_wl1 < pkt_ack ||
                                                       (tcb.snd_wl1 == pkt_ack &&
                                                        tcb.snd_wl2 <= pkt_ack) {
                                                        tcb.snd_wnd = pkt_window;
                                                        trace!("snd_wnd = {:?}", tcb.snd_wnd);
                                                        tcb.snd_wl1 = pkt_seq_num;
                                                        tcb.snd_wl2 = pkt_ack;
                                                    }
                                                } else if pkt_ack < tcb.snd_una {
                                                    info!("ignoring duplicate ACK");
                                                    break;
                                                } else if pkt_ack > tcb.snd_nxt {
                                                    warn!("Dropping segment, received too early, sending ACK");
                                                    // Send ACK
                                                    t_params = TcpParams {
                                                        src_port: tcb.local_port,
                                                        dst_port: tcb.remote_port,
                                                        seq_num: tcb.snd_nxt,
                                                        ack_num: tcb.rcv_nxt,
                                                        flags: TcpFlags::ACK,
                                                        window: tcb.rcv_wnd,
                                                    };
                                                    build_tcp_header(t_params,
                                                                     lip,
                                                                     dip,
                                                                     None,
                                                                     &mut pkt_buf);
                                                    should_send_packet = true;
                                                    break;
                                                }

                                                // TODO more specific processing, see pg. 73
                                                match tcb.state {
                                                    STATUS::FinWait1 => {}
                                                    STATUS::FinWait2 => {}
                                                    STATUS::CloseWait => {}
                                                    STATUS::Closing => {}
                                                    _ => {}
                                                }

                                                // TODO payload processing, see pg. 74
                                                match tcb.state {
                                                    STATUS::Estab | STATUS::FinWait1 |
                                                    STATUS::FinWait2 => {
                                                        // TODO put the received segment in the right
                                                        // place in the buffer
                                                        if tcb.rcv_nxt - tcb.irs + seg_len <=
                                                           tcb.rcv_wnd as u32 {
                                                            debug!("Appending to socket: {:?}, {:?}",
                                                                   tcb.remote_ip,
                                                                   tcb.remote_port);
                                                            tcb.rcv_buffer
                                                                .append(&mut pkt.payload()
                                                                    .to_vec());
                                                            tcb.rcv_wnd -= seg_len as u16;
                                                            trace!("rcv_wnd = {:?}", tcb.rcv_wnd);
                                                            tcb.rcv_nxt = pkt_seq_num + seg_len;
                                                            // TODO adjust rcv window

                                                            // Send ACK
                                                            t_params = TcpParams {
                                                                src_port: tcb.local_port,
                                                                dst_port: tcb.remote_port,
                                                                seq_num: tcb.snd_nxt,
                                                                ack_num: tcb.rcv_nxt,
                                                                flags: TcpFlags::ACK,
                                                                window: tcb.rcv_wnd,
                                                            };
                                                            build_tcp_header(t_params,
                                                                             lip,
                                                                             dip,
                                                                             None,
                                                                             &mut pkt_buf);
                                                            should_send_packet = true;
                                                        } else {
                                                            warn!("No place in recv window!");
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            STATUS::LastAck => {}
                                            STATUS::TimeWait => {}
                                            _ => {}
                                        }


                                    } else {
                                        warn!("Dropping packet, no ACK flag set");
                                        break;
                                    }
                                } else {
                                    // TODO non-ideal case, ie, might need trimming
                                }
                            } else {
                                warn!("Dropping packet, unacceptable! Sending ACK...");
                                t_params = TcpParams {
                                    src_port: tcb.local_port,
                                    dst_port: tcb.remote_port,
                                    seq_num: tcb.snd_nxt,
                                    ack_num: tcb.rcv_nxt,
                                    flags: TcpFlags::ACK,
                                    window: tcb.rcv_wnd,
                                };
                                build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                                should_send_packet = true;
                            }
                        }
                    }
                }
                break;
            }
        }

        if !found_match {
            for (sock, tcb) in &mut tcp.tc_blocks {
                // listening socket
                if tcb.local_ip == lip && tcb.local_port == lp && tcb.state == STATUS::Listen {
                    debug!("found matching listening socket");
                    // new connection
                    if pkt_flags == TcpFlags::SYN {
                        let mut ntcb = TCB::new();
                        ntcb.local_ip = lip;
                        ntcb.local_port = lp;
                        ntcb.remote_ip = dip;
                        ntcb.remote_port = dp;

                        ntcb.rcv_nxt = pkt_seq_num + 1;
                        ntcb.irs = pkt_seq_num;
                        ntcb.snd_wnd = pkt_window;
                        ntcb.snd_nxt = ntcb.iss + 1;
                        ntcb.snd_una = ntcb.iss;
                        ntcb.state = STATUS::SynRcvd;

                        tcp.bound_ports.insert((ntcb.local_ip, ntcb.local_port));

                        t_params = TcpParams {
                            src_port: tcb.local_port,
                            dst_port: ntcb.remote_port,
                            seq_num: ntcb.iss,
                            ack_num: ntcb.rcv_nxt,
                            flags: TcpFlags::SYN | TcpFlags::ACK,
                            window: ntcb.rcv_wnd,
                        };
                        build_tcp_header(t_params, lip, dip, None, &mut pkt_buf);
                        should_send_packet = true;
                        tcb.conns_q.push_back(ntcb);
                    } else if pkt_flags == TcpFlags::ACK {
                        for ntcb in &mut tcb.conns_q {
                            if ntcb.state == STATUS::SynRcvd && ntcb.remote_ip == dip &&
                               ntcb.remote_port == dp {
                                // TODO check for correct ack
                                ntcb.state = STATUS::Estab;
                                parent_socket = *sock;
                                need_new_tcb = true;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }

        if need_new_tcb {
            // only when accepting a new connection
            let sock_id = match tcp.free_sockets.pop() {
                Some(socket) => socket,
                None => tcp.tc_blocks.len(),
            };

            let tcb: TCB;
            {
                let conns_q = &mut tcp.tc_blocks.get_mut(&parent_socket).unwrap().conns_q;
                tcb = conns_q.pop_front().unwrap();
            }

            match tcp.tc_blocks.insert(sock_id, tcb) {
                Some(v) => {
                    warn!("overwrote exisiting value: {:?}", v);
                }
                None => {
                    println!("v_accept on socket {} returned {}", parent_socket, sock_id);
                }
            }
        }

        if mark_tcb_for_deletion {
            let tcb = tcp.tc_blocks.remove(&sock_to_be_deleted).unwrap();
            tcp.free_sockets.push(sock_to_be_deleted);
            tcp.bound_ports.remove(&(tcb.local_ip, tcb.local_port));
        }
    }

    if should_send_packet {
        let segment = TcpPacket::new(&pkt_buf[..]).unwrap();
        ip::send(dl_ctx,
                 Some(rip_ctx),
                 Some(tcp_ctx),
                 ip_params,
                 TCP_PROT,
                 rip::INFINITY,
                 segment.packet().to_vec(),
                 0,
                 true)
            .unwrap();
    }
}

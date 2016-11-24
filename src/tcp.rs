use std::collections::{HashMap, HashSet, BTreeMap};
use std::net::Ipv4Addr;
use std::str;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use bytes::{Buf, BufMut};
use bytes_more::RingBuf;
use crossbeam::sync::MsQueue;
use pnet::packet::FromPacket;
use pnet::packet::Packet;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket, TcpFlags};
use pnet_macros_support::types::*;
use rand;

use datalink::DataLink;
use ip;
use rip::{self, RipCtx};

const TCP_PROT: u8 = 6;
const TCP_MAX_WINDOW_SZ: usize = 65535;
const RTO: u64 = 10000; //ms

#[derive(Default)]
pub struct TCP {
    // container of TCBs
    tc_blocks: HashMap<usize, Arc<RwLock<TCB>>>,
    free_sockets: Vec<usize>,
    invalidated_socks: HashSet<usize>,
    unreadable_socks: HashSet<usize>,
    bound_ports: HashSet<(Ipv4Addr, u16)>,
    fourtup_to_sock: HashMap<FourTup, usize>,
    sock_to_sender: HashMap<usize, Arc<MsQueue<Message>>>,
}

#[derive(Debug)]
#[derive(Hash, PartialEq, Eq)]
struct FourTup {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Message {
    UserCall { call: UserCallKind },
    Timeout { to: TimeoutKind },
    IpRecv { pkt: SegmentIpParams },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum UserCallKind {
    Open { dst_addr: Ipv4Addr, port: u16 },
    Send { buffer: Vec<u8> },
    Receive { num_bytes: usize },
    Close,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum TimeoutKind {
    Retransmission { seq_num: u32 },
    TimeWaitTO,
}

#[derive(Debug)]
pub struct SegmentIpParams {
    pub pkt_buf: Vec<u8>,
    pub params: ip::IpParams,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
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
struct TCB {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    state: Status,

    snd_buffer: RingBuf, // user's send buffer
    rcv_buffer: RingBuf, // user's receive buffer
    seg_q: BTreeMap<u32, Vec<u8>>,
    // TODO consider storing only index into snd_buffer instead of complete segment
    retransmit_q: BTreeMap<u32, SegmentIpParams>,

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

    // recv end of channel
    qr: Option<Arc<MsQueue<Message>>>,

    // only for LISTEN
    conns_map: HashMap<(Ipv4Addr, u16), TCB>,
    qs: Option<Arc<MsQueue<TCB>>>,

    // response channels
    connect_resp: Arc<MsQueue<Result<(), String>>>,
    write_resp: Arc<MsQueue<Result<(), String>>>,
    read_resp: Arc<MsQueue<Option<()>>>,
}

impl TCB {
    fn new(qr: Option<Arc<MsQueue<Message>>>) -> TCB {
        TCB {
            local_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            local_port: 0,
            remote_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            remote_port: 0,
            state: Status::Closed,

            snd_buffer: RingBuf::with_capacity(TCP_MAX_WINDOW_SZ + 1),
            rcv_buffer: RingBuf::with_capacity(TCP_MAX_WINDOW_SZ + 1),
            seg_q: BTreeMap::new(),
            retransmit_q: BTreeMap::new(),

            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: TCP_MAX_WINDOW_SZ as u16,
            snd_wl1: 0,
            snd_wl2: 0,
            iss: rand::random::<u16>() as u32,

            rcv_nxt: 0,
            rcv_wnd: TCP_MAX_WINDOW_SZ as u16,
            irs: rand::random::<u16>() as u32,

            qr: qr,

            conns_map: HashMap::new(),
            qs: None,

            connect_resp: Arc::new(MsQueue::new()),
            write_resp: Arc::new(MsQueue::new()),
            read_resp: Arc::new(MsQueue::new()),
        }
    }
}

#[derive(Debug)]
pub struct Socket {
    pub socket_id: usize,
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
    pub status: Status,
}

struct TcpParams {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u9be,
    window: u16be,
}

impl TCP {
    pub fn new() -> TCP {
        info!("Starting TCP...");
        TCP {
            tc_blocks: HashMap::new(),
            free_sockets: Vec::new(),
            invalidated_socks: HashSet::new(),
            unreadable_socks: HashSet::new(),
            bound_ports: HashSet::new(),
            fourtup_to_sock: HashMap::new(),
            sock_to_sender: HashMap::new(),
        }
    }

    pub fn get_sockets(&self) -> Vec<Socket> {
        self.tc_blocks
            .iter()
            .map(|(sock, tcb)| {
                let tcb = &(*tcb.read().unwrap());
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

    pub fn get_snd_wnd_sz(&self, sock: usize) -> Result<u16, String> {
        match self.tc_blocks.get(&sock) {
            Some(tcb) => Ok((*tcb.read().unwrap()).snd_wnd),
            None => Err("No matching TCB found!".to_owned()),
        }
    }

    pub fn get_rcv_wnd_sz(&self, sock: usize) -> Result<u16, String> {
        match self.tc_blocks.get(&sock) {
            Some(tcb) => Ok((*tcb.read().unwrap()).rcv_wnd),
            None => Err("No matching TCB found!".to_owned()),
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

    pub fn v_bind(&mut self,
                  dl_ctx: &Arc<RwLock<DataLink>>,
                  socket: usize,
                  addr: Option<Ipv4Addr>,
                  port: u16)
                  -> Result<(), String> {
        if self.invalidated_socks.contains(&socket) {
            return Err(format!("error: socket {:?} is invalidated", socket));
        }

        info!("Binding to IP {:?}, port {}", addr, port);
        match self.tc_blocks.get(&socket) {
            Some(tcb) => {
                let tcb = &mut (*tcb.write().unwrap());
                let ifaces = (*dl_ctx.read().unwrap()).get_interfaces();
                for iface in ifaces {
                    if !self.bound_ports.contains(&(iface.src, port)) {
                        tcb.local_ip = addr.unwrap_or_else(|| iface.src);
                        tcb.local_port = port;
                        // remote ip and port are zeros from v_socket()
                        self.bound_ports.insert((tcb.local_ip, port));
                        self.fourtup_to_sock.insert(FourTup {
                                                        src_ip: tcb.local_ip,
                                                        src_port: port,
                                                        dst_ip: "0.0.0.0"
                                                            .parse::<Ipv4Addr>()
                                                            .unwrap(),
                                                        dst_port: 0,
                                                    },
                                                    socket);
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
        if self.invalidated_socks.contains(&socket) {
            return Err(format!("error: socket {:?} is invalidated", socket));
        }

        let ip_port = self.get_unused_ip_port(dl_ctx).unwrap();
        match self.tc_blocks.get(&socket) {
            Some(tcb) => {
                let tcb = &mut (*tcb.write().unwrap());
                if tcb.local_port == 0 {
                    tcb.local_ip = ip_port.0;
                    tcb.local_port = ip_port.1;
                    self.bound_ports.insert((tcb.local_ip, tcb.local_port));
                }
                tcb.state = Status::Listen;
                tcb.qs = Some(Arc::new(MsQueue::new()));
                info!("TCB state changed to LISTEN");
                Ok(())
            }
            None => Err("No TCB associated with this connection!".to_owned()),
        }
    }
}

pub fn v_socket(tcp_ctx: &Arc<RwLock<TCP>>,
                dl_ctx: &Arc<RwLock<DataLink>>,
                rip_ctx: &Arc<RwLock<RipCtx>>)
                -> Result<usize, String> {
    trace!("Creating socket...");

    let qr = Arc::new(MsQueue::new());
    let tcb_clone: Arc<RwLock<TCB>>;
    let res = {
        let tcp = &mut (*tcp_ctx.write().unwrap());
        let sock_id = match tcp.free_sockets.pop() {
            Some(socket) => socket,
            None => tcp.tc_blocks.len(),
        };

        tcp.sock_to_sender.insert(sock_id, qr.clone());

        let tcb = Arc::new(RwLock::new(TCB::new(Some(qr.clone()))));
        tcb_clone = tcb.clone();

        match tcp.tc_blocks.insert(sock_id, tcb) {
            Some(v) => {
                warn!("overwrote exisiting value: {:?}", v);
                Ok(sock_id)
            }
            None => Ok(sock_id),
        }
    };

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    let tcp_ctx_clone = tcp_ctx.clone();
    thread::spawn(move || {
        conn_state_machine(tcb_clone, qr, dl_ctx_clone, rip_ctx_clone, tcp_ctx_clone)
    });

    res
}

pub fn v_accept(tcp_ctx: Arc<RwLock<TCP>>,
                dl_ctx: Arc<RwLock<DataLink>>,
                rip_ctx: Arc<RwLock<RipCtx>>,
                socket: usize,
                addr: Option<Ipv4Addr>)
                -> Result<usize, String> {
    if (*tcp_ctx.read().unwrap()).invalidated_socks.contains(&socket) {
        return Err(format!("error: socket {:?} is invalidated", socket));
    }

    if let Some(addr) = addr {
        debug!{"v_accept called for addr: {:?}", addr};
    }
    let qr = Arc::new(MsQueue::new());
    let tcb_clone: Option<Arc<RwLock<TCB>>>;
    let mut ltcb_qr = Arc::new(MsQueue::new());
    {
        let tcp = &(*tcp_ctx.read().unwrap());
        let ltcb = tcp.tc_blocks[&socket].clone();
        let ltcb = &(*ltcb.read().unwrap());
        if let Some(ref qs) = ltcb.qs {
            ltcb_qr = qs.clone();
        }
    }

    trace!("accept thread for socket {} going to block", socket);
    // blocks
    let ntcb = ltcb_qr.pop();

    let res = {
        let tcp = &mut (*tcp_ctx.write().unwrap());
        let sock_id = match tcp.free_sockets.pop() {
            Some(socket) => socket,
            None => tcp.tc_blocks.len(),
        };

        tcp.sock_to_sender.insert(sock_id, qr.clone());
        let tcb = Arc::new(RwLock::new(TCB { qr: Some(qr.clone()), ..ntcb }));
        tcp.fourtup_to_sock.insert(FourTup {
                                       src_ip: ntcb.local_ip,
                                       src_port: ntcb.local_port,
                                       dst_ip: ntcb.remote_ip,
                                       dst_port: ntcb.remote_port,
                                   },
                                   sock_id);

        tcb_clone = Some(tcb.clone());

        match tcp.tc_blocks.insert(sock_id, tcb) {
            Some(v) => {
                warn!("overwrote exisiting value: {:?}", v);
                Ok(sock_id)
            }
            None => Ok(sock_id),
        }
    };
    thread::spawn(move || conn_state_machine(tcb_clone.unwrap(), qr, dl_ctx, rip_ctx, tcp_ctx));
    res
}

fn build_tcp_header(t_params: TcpParams,
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
    // number of 32-bit words in header
    tcp_packet.set_data_offset((TcpPacket::minimum_packet_size() / 4) as u4);
    tcp_packet.set_flags(t_params.flags);
    tcp_packet.set_window(t_params.window);
    if let Some(payload) = payload {
        tcp_packet.set_payload(payload)
    }
    let cksum = ipv4_checksum(&tcp_packet.to_immutable(), src_addr, dst_addr);
    tcp_packet.set_checksum(cksum);
}

// TODO consider moving inside impl TCP
pub fn v_connect(tcp_ctx: &Arc<RwLock<TCP>>,
                 rip_ctx: &Arc<RwLock<RipCtx>>,
                 socket: usize,
                 dst_addr: Ipv4Addr,
                 port: u16)
                 -> Result<(), String> {
    {
        if (*tcp_ctx.read().unwrap()).invalidated_socks.contains(&socket) {
            return Err(format!("error: socket {:?} is invalidated", socket));
        }
    }

    {
        let tcp = &mut *tcp_ctx.write().unwrap();
        if let Some(tcb) = tcp.tc_blocks.get(&socket) {
            let tcb = &mut (*tcb.write().unwrap());
            if tcb.state == Status::Closed {
                let local_ip = (*rip_ctx.read().unwrap()).get_next_hop(dst_addr).unwrap();
                let mut unused_port: u16 = 0;
                for port in 1024..65535 {
                    if !tcp.bound_ports.contains(&(local_ip, port)) {
                        unused_port = port;
                        break;
                    }
                }

                if unused_port == 0 {
                    return Err("Ran out of free ports!".to_owned());
                }

                tcb.local_ip = local_ip;
                tcb.local_port = unused_port;

                tcp.bound_ports.insert((local_ip, unused_port));
                tcp.fourtup_to_sock.insert(FourTup {
                                               src_ip: local_ip,
                                               src_port: unused_port,
                                               dst_ip: dst_addr,
                                               dst_port: port,
                                           },
                                           socket);
            } else {
                info!("v_connect called on non-closed socket");
            }
        } else {
            return Err("ENOTSOCK: No TCB associated with this connection!".to_owned());
        }
    }

    let conn_qr: Arc<MsQueue<Result<(), String>>>;
    {
        let tcp = &(*tcp_ctx.read().unwrap());
        let tcb = tcp.tc_blocks[&socket].clone();
        let tcb = &(*tcb.read().unwrap());
        conn_qr = tcb.connect_resp.clone();

        match tcp.sock_to_sender.get(&socket) {
            Some(qs) => {
                qs.push(Message::UserCall {
                    call: UserCallKind::Open {
                        dst_addr: dst_addr,
                        port: port,
                    },
                });
            }
            None => return Err("ENOTSOCK: No TCB associated with this connection!".to_owned()),
        }
    }

    trace!("connect thread for socket {} going to block", socket);
    // blocks
    conn_qr.pop()
}

// TODO consider moving inside one of impl TCP or TCB
pub fn v_read(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, size: usize) -> Result<Vec<u8>, String> {
    if (*tcp_ctx.read().unwrap()).invalidated_socks.contains(&socket) {
        return Err(format!("error: socket {:?} is invalidated", socket));
    }
    if (*tcp_ctx.read().unwrap()).unreadable_socks.contains(&socket) {
        return Err(format!("error: socket {:?} is not readable anymore", socket));
    }

    let read_qr: Arc<MsQueue<Option<()>>>;
    {
        let tcp = &(*tcp_ctx.read().unwrap());
        let tcb = tcp.tc_blocks[&socket].clone();
        let tcb = &(*tcb.read().unwrap());
        read_qr = tcb.read_resp.clone();

        match tcp.sock_to_sender.get(&socket) {
            Some(qs) => {
                qs.push(Message::UserCall { call: UserCallKind::Receive { num_bytes: size } });
            }
            None => return Err("ENOTSOCK: No TCB associated with this connection!".to_owned()),
        }
    }

    trace!("v_read() for socket {} going to block", socket);
    // blocks
    if read_qr.pop().is_some() {
        let mut ret = vec![0u8; size];
        let tcp = &(*tcp_ctx.read().unwrap());
        let tcb = tcp.tc_blocks[&socket].clone();
        let tcb = &mut (*tcb.write().unwrap());
        tcb.rcv_buffer.copy_to_slice(&mut ret);
        Ok(ret)
    } else {
        // EOF
        Ok(vec![])
    }
}

// TODO consider moving inside one of impl TCP or TCB
pub fn v_write(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, message: &[u8]) -> Result<usize, String> {
    if (*tcp_ctx.read().unwrap()).invalidated_socks.contains(&socket) {
        return Err(format!("error: socket {:?} is invalidated", socket));
    }

    trace!("Message: {:?}", message);

    let write_qr: Arc<MsQueue<Result<(), String>>>;
    {
        let tcp = &(*tcp_ctx.read().unwrap());
        let tcb = tcp.tc_blocks[&socket].clone();
        let tcb = &(*tcb.read().unwrap());
        write_qr = tcb.write_resp.clone();

        match tcp.sock_to_sender.get(&socket) {
            Some(qs) => {
                qs.push(Message::UserCall {
                    call: UserCallKind::Send { buffer: message.to_vec() },
                });
            }
            None => return Err("ENOTSOCK: No TCB associated with this connection!".to_owned()),
        }
    }

    trace!("v_write for socket {} going to block", socket);
    // blocks
    if write_qr.pop().is_ok() {
        Ok(message.len())
    } else {
        // should never happen
        Err("write failed".to_owned())
    }
}

pub fn v_shutdown(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, mode: usize) -> Result<(), String> {
    // if (*tcp_ctx.read().unwrap()).invalidated_socks.contains(&socket) {
    // return Err(format!("error: socket {:?} is invalidated", socket));
    // }
    //
    let tcp = &mut *tcp_ctx.write().unwrap();
    if tcp.tc_blocks.get(&socket).is_none() {
        Err(format!("No TCB exists for given socket: {:?}", socket))
    } else {
        let qs = tcp.sock_to_sender[&socket].clone();
        match mode {
            1 => {
                // write
                qs.push(Message::UserCall { call: UserCallKind::Close });
                Ok(())
            }
            2 => {
                // read
                tcp.unreadable_socks.insert(socket);
                // TODO make sure window size doesn't grow anymore
                Ok(())
            }
            3 => {
                // both
                tcp.unreadable_socks.insert(socket);
                // TODO make sure window size doesn't grow anymore
                qs.push(Message::UserCall { call: UserCallKind::Close });
                Ok(())
            }
            _ => Err(format!("invalid type: {:?}", mode)),
        }
    }
}

pub fn v_close(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize) -> Result<(), String> {
    if (*tcp_ctx.read().unwrap()).invalidated_socks.contains(&socket) {
        return Err(format!("error: socket {:?} is already invalidated", socket));
    }

    let res: Result<(), String>;

    {
        let tcp = &mut *tcp_ctx.write().unwrap();
        res = if tcp.tc_blocks.get(&socket).is_some() {
            tcp.invalidated_socks.insert(socket);
            Ok(())
        } else {
            Err(format!("No TCB exists for given socket: {:?}", socket))
        }
    }

    if res.is_ok() {
        v_shutdown(tcp_ctx, socket, 1)
    } else {
        res
    }
}

// TODO consider moving inside impl TCP
pub fn demux(tcp_ctx: &Arc<RwLock<TCP>>, pkt: SegmentIpParams) -> Result<(), String> {
    let four_tup: FourTup;
    {
        let segment = TcpPacket::new(&pkt.pkt_buf).unwrap();
        four_tup = FourTup {
            src_ip: pkt.params.dst,
            src_port: segment.get_destination(),
            dst_ip: pkt.params.src,
            dst_port: segment.get_source(),
        };
    }
    let tcp = &(*tcp_ctx.read().unwrap());
    match tcp.fourtup_to_sock.get(&four_tup) {
        Some(sock) => {
            match tcp.sock_to_sender.get(sock) {
                Some(qs) => {
                    qs.push(Message::IpRecv { pkt: pkt });
                    Ok(())
                }
                None => Err("No matching sender found!".to_owned()),
            }
        }
        None => {
            let four_tup = FourTup {
                dst_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
                dst_port: 0,
                ..four_tup
            };
            match tcp.fourtup_to_sock.get(&four_tup) {
                Some(sock) => {
                    match tcp.sock_to_sender.get(sock) {
                        Some(qs) => {
                            qs.push(Message::IpRecv { pkt: pkt });
                            Ok(())
                        }
                        None => Err("No matching sender found!".to_owned()),
                    }
                }
                None => {
                    debug!("{:?}", tcp.fourtup_to_sock);
                    debug!("{:?}", four_tup);
                    Err("No matching sock found!".to_owned())
                }
            }
        }
    }
}

#[allow(unknown_lints)]
#[allow(cyclomatic_complexity)]
fn conn_state_machine(tcb_ref: Arc<RwLock<TCB>>,
                      qr: Arc<MsQueue<Message>>,
                      dl_ctx: Arc<RwLock<DataLink>>,
                      rip_ctx: Arc<RwLock<RipCtx>>,
                      tcp_ctx: Arc<RwLock<TCP>>) {
    use self::Message::*;
    loop {
        // blocks
        let msg = qr.pop();

        let mut should_send_packet = false;
        let mut t_params: TcpParams;
        let mut pkt_sz = MutableTcpPacket::minimum_packet_size();
        let mut ip_params = ip::IpParams {
            src: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            dst: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            len: pkt_sz, // TODO make sure this gets updated correctly for send call
            tos: 0,
            opt: vec![],
        };
        let mut pkt_buf = vec![0u8; pkt_sz];

        match msg {
            UserCall { call } => {
                use self::UserCallKind::*;
                use self::Status::*;
                match call {
                    // only handling active open here
                    Open { dst_addr, port } => {
                        debug!("Open {:?} {:?}", dst_addr, port);
                        let tcb = &mut (*tcb_ref.write().unwrap());
                        trace!("Took write lock on TCB");
                        match tcb.state {
                            Closed => {
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

                                build_tcp_header(t_params,
                                                 tcb.local_ip,
                                                 dst_addr,
                                                 None,
                                                 &mut pkt_buf);
                                ip_params = ip::IpParams {
                                    src: tcb.local_ip,
                                    dst: dst_addr,
                                    ..ip_params
                                };

                                tcb.snd_una = tcb.iss;
                                tcb.snd_nxt = tcb.iss + 1;

                                debug!("State set to SynSent");
                                tcb.state = Status::SynSent;

                                should_send_packet = true;
                            }
                            Listen => {
                                // TODO XXX test this code path
                                tcb.remote_ip = dst_addr;
                                tcb.remote_port = port;
                                // TODO see pg. 54 to confirm
                                tcb.iss = rand::random::<u16>() as u32;

                                t_params = TcpParams {
                                    src_port: tcb.local_port,
                                    dst_port: tcb.remote_port,
                                    seq_num: tcb.iss,
                                    ack_num: 0,
                                    flags: TcpFlags::SYN,
                                    window: tcb.rcv_wnd,
                                };

                                build_tcp_header(t_params,
                                                 tcb.local_ip,
                                                 dst_addr,
                                                 None,
                                                 &mut pkt_buf);
                                // TODO take care of SEND here
                                ip_params = ip::IpParams {
                                    src: tcb.local_ip,
                                    dst: dst_addr,
                                    ..ip_params
                                };

                                tcb.snd_una = tcb.iss;
                                tcb.snd_nxt = tcb.iss + 1;
                                info!("Switching a Listening socket to SynSent");
                                tcb.state = Status::SynSent;

                                should_send_packet = true;
                            }
                            _ => {
                                error!("connection already exists");
                            }
                        }
                    }
                    Send { buffer } => {
                        let tcb = &mut (*tcb_ref.write().unwrap());
                        #[allow(match_same_arms)]
                        match tcb.state {
                            Closed => {
                                error!("connection does not exist");
                            }
                            Listen => {
                                // TODO see if we can introduce foreign socket
                                error!("foreign socket unspecified (called SEND on Listen state)");
                            }
                            SynSent | SynRcvd => {
                                info!("Not in Estab yet, requeueing buffer");
                                if let Some(ref qs) = tcb.qr {
                                    qs.push(Message::UserCall {
                                        call: UserCallKind::Send { buffer: buffer },
                                    });
                                }
                            }
                            Estab | CloseWait => {
                                if buffer.len() < tcb.snd_buffer.remaining_write() {
                                    tcb.snd_buffer.copy_from_slice(&buffer);
                                    tcb.write_resp.push(Ok(()));

                                    // send the segment
                                    let num_bytes = if (tcb.snd_wnd as usize) <
                                                       tcb.snd_buffer.remaining() {
                                        tcb.snd_wnd as usize
                                    } else {
                                        tcb.snd_buffer.remaining()
                                    };

                                    t_params = TcpParams {
                                        src_port: tcb.local_port,
                                        dst_port: tcb.remote_port,
                                        seq_num: tcb.snd_nxt,
                                        ack_num: tcb.rcv_nxt,
                                        flags: TcpFlags::ACK,
                                        window: tcb.rcv_wnd,
                                    };
                                    pkt_buf =
                                        vec![0u8; TcpPacket::minimum_packet_size() + num_bytes];
                                    trace!("snd_buf.pos: {:?}", tcb.snd_buffer.position());
                                    tcb.snd_buffer
                                        .copy_to_slice(&mut pkt_buf[TcpPacket::minimum_packet_size()..]);
                                    trace!("snd_buf.pos (new): {:?}", tcb.snd_buffer.position());
                                    build_tcp_header(t_params,
                                                     tcb.local_ip,
                                                     tcb.remote_ip,
                                                     None,
                                                     &mut pkt_buf);
                                    {
                                        let segment = MutableTcpPacket::new(&mut pkt_buf).unwrap();
                                        pkt_sz =
                                            MutableTcpPacket::packet_size(&segment.from_packet());
                                    }
                                    ip_params = ip::IpParams {
                                        src: tcb.local_ip,
                                        dst: tcb.remote_ip,
                                        len: pkt_sz,
                                        ..ip_params
                                    };

                                    // TODO confirm if this needs to be done here
                                    tcb.snd_nxt += num_bytes as u32;

                                    should_send_packet = true;
                                } else {
                                    error!("SEND: insufficent resources, requeuing");
                                    if let Some(ref qs) = tcb.qr {
                                        qs.push(Message::UserCall {
                                            call: UserCallKind::Send { buffer: buffer },
                                        });
                                    }
                                }
                            }
                            _ => {
                                error!("connection closing");
                            }
                        }
                    }
                    Receive { num_bytes } => {
                        let tcb = &mut (*tcb_ref.write().unwrap());
                        #[allow(match_same_arms)]
                        match tcb.state {
                            Closed => {
                                error!("connection does not exist");
                            }
                            Listen | SynSent | SynRcvd => {
                                info!("Not in Estab yet, requeueing request");
                                if let Some(ref qs) = tcb.qr {
                                    qs.push(Message::UserCall {
                                        call: UserCallKind::Receive { num_bytes: num_bytes },
                                    });
                                }
                            }
                            Estab | FinWait1 | FinWait2 => {
                                // Remove acknowledged segments from seg_q
                                let seq_nums: Vec<_> = tcb.seg_q.keys().cloned().collect();
                                for seq_num in seq_nums {
                                    if seq_num > tcb.rcv_nxt {
                                        break;
                                    }
                                    if let Some(seg) = tcb.seg_q.remove(&seq_num) {
                                        tcb.rcv_buffer.copy_from_slice(&seg);
                                    }
                                }
                                if tcb.rcv_buffer.remaining() >= num_bytes {
                                    tcb.read_resp.push(Some(()));
                                } else if let Some(ref qs) = tcb.qr {
                                    qs.push(Message::UserCall {
                                        call: UserCallKind::Receive { num_bytes: num_bytes },
                                    });
                                }
                            }
                            CloseWait => {
                                // Remove acknowledged segments from seg_q
                                let seq_nums: Vec<_> = tcb.seg_q.keys().cloned().collect();
                                for seq_num in seq_nums {
                                    if seq_num > tcb.rcv_nxt {
                                        break;
                                    }
                                    if let Some(seg) = tcb.seg_q.remove(&seq_num) {
                                        tcb.rcv_buffer.copy_from_slice(&seg);
                                    }
                                }
                                if tcb.rcv_buffer.remaining() >= num_bytes {
                                    tcb.read_resp.push(Some(()));
                                } else {
                                    error!("connection closing");
                                    tcb.read_resp.push(None);
                                }
                            }
                            _ => {
                                error!("connection closing");
                            }
                        }
                    }
                    Close => {
                        let tcb = &mut (*tcb_ref.write().unwrap());
                        match tcb.state {
                            Closed => {
                                error!("connection does not exist");
                            }
                            Listen => {
                                // TODO qs.push the following for outstanding receives
                                // error!("closing");
                                tcb.state = Closed;
                                (*tcp_ctx.write().unwrap())
                                    .bound_ports
                                    .remove(&(tcb.local_ip, tcb.local_port));
                                break; // delete TCB
                            }
                            SynSent => {
                                tcb.write_resp.push(Err("closing".to_owned()));
                                // TODO qs.push the following for outstanding receives
                                // error!("closing");
                                tcb.state = Closed;
                                break; // delete TCB
                            }
                            SynRcvd => {
                                // TODO also check if there are pending SENDs
                                if tcb.snd_buffer.remaining() == 0 {
                                    t_params = TcpParams {
                                        src_port: tcb.local_port,
                                        dst_port: tcb.remote_port,
                                        seq_num: tcb.snd_nxt,
                                        ack_num: tcb.rcv_nxt,
                                        flags: TcpFlags::FIN,
                                        window: tcb.rcv_wnd,
                                    };

                                    build_tcp_header(t_params,
                                                     tcb.local_ip,
                                                     tcb.remote_ip,
                                                     None,
                                                     &mut pkt_buf);
                                    ip_params = ip::IpParams {
                                        src: tcb.local_ip,
                                        dst: tcb.remote_ip,
                                        ..ip_params
                                    };

                                    info!("switching to FinWait1 from Estab");
                                    tcb.state = FinWait1;

                                    should_send_packet = true;
                                } else {
                                    info!("Not in Estab yet, requeueing CLOSE");
                                    if let Some(ref qs) = tcb.qr {
                                        qs.push(Message::UserCall { call: UserCallKind::Close });
                                    }
                                }
                            }
                            Estab => {

                                // TODO also check if there are pending SENDs
                                if tcb.snd_buffer.remaining() != 0 {
                                    info!("pending sends, requeueing CLOSE");
                                    if let Some(ref qs) = tcb.qr {
                                        qs.push(Message::UserCall { call: UserCallKind::Close });
                                    }
                                } else {
                                    t_params = TcpParams {
                                        src_port: tcb.local_port,
                                        dst_port: tcb.remote_port,
                                        seq_num: tcb.snd_nxt,
                                        ack_num: tcb.rcv_nxt,
                                        flags: TcpFlags::FIN,
                                        window: tcb.rcv_wnd,
                                    };

                                    build_tcp_header(t_params,
                                                     tcb.local_ip,
                                                     tcb.remote_ip,
                                                     None,
                                                     &mut pkt_buf);
                                    ip_params = ip::IpParams {
                                        src: tcb.local_ip,
                                        dst: tcb.remote_ip,
                                        ..ip_params
                                    };

                                    should_send_packet = true;
                                }

                                info!("switching to FinWait1 from Estab");
                                tcb.state = FinWait1;
                            }
                            FinWait1 | FinWait2 => {
                                error!("connection closing");
                            }
                            CloseWait => {
                                // TODO also check if there are pending SENDs
                                if tcb.snd_buffer.remaining() != 0 {
                                    info!("pending sends, requeueing CLOSE");
                                    if let Some(ref qs) = tcb.qr {
                                        qs.push(Message::UserCall { call: UserCallKind::Close });
                                    }
                                } else {
                                    t_params = TcpParams {
                                        src_port: tcb.local_port,
                                        dst_port: tcb.remote_port,
                                        seq_num: tcb.snd_nxt,
                                        ack_num: tcb.rcv_nxt,
                                        flags: TcpFlags::FIN,
                                        window: tcb.rcv_wnd,
                                    };

                                    build_tcp_header(t_params,
                                                     tcb.local_ip,
                                                     tcb.remote_ip,
                                                     None,
                                                     &mut pkt_buf);
                                    ip_params = ip::IpParams {
                                        src: tcb.local_ip,
                                        dst: tcb.remote_ip,
                                        ..ip_params
                                    };

                                    info!("switching to Closing from CloseWait");
                                    tcb.state = Closing;

                                    should_send_packet = true;
                                }
                            }
                            _ => {
                                error!("connection closing");
                            }
                        }
                    }
                }
            }
            Timeout { to } => {
                use self::TimeoutKind::*;
                #[allow(match_same_arms)]
                let tcb = &mut (*tcb_ref.write().unwrap());
                match to {
                    Retransmission { seq_num } => {
                        if let Some(pkt) = tcb.retransmit_q.get(&seq_num) {
                            let segment = TcpPacket::new(&pkt.pkt_buf).unwrap();
                            if segment.get_sequence() == seq_num {
                                if let Some(ref qs) = tcb.qr {
                                    let qs = qs.clone();
                                    thread::spawn(move || {
                                        let rto = Duration::from_millis(RTO);
                                        thread::sleep(rto);
                                        qs.push(Message::Timeout {
                                            to: TimeoutKind::Retransmission { seq_num: seq_num },
                                        });
                                    });

                                    pkt_buf = pkt.pkt_buf.clone();
                                    ip_params = pkt.params.clone();

                                    should_send_packet = true;
                                }
                            }
                        };
                    }
                    TimeWaitTO => {
                        tcb.state = Status::Closed;
                        break; // delete TCB
                    }
                }
            }
            IpRecv { pkt } => {
                let segment = pkt.pkt_buf;
                let pkt_ip_params = pkt.params;
                let pkt = TcpPacket::new(&segment).unwrap();
                trace!("{:?}", pkt);
                // TODO verify checksum
                let pkt_seq_num = pkt.get_sequence();
                let pkt_ack = pkt.get_acknowledgement();
                let pkt_flags = pkt.get_flags();
                let pkt_window = pkt.get_window();

                let pkt_size = pkt_ip_params.len;

                let (lip, lp, dip, dp) =
                    (pkt_ip_params.dst, pkt.get_destination(), pkt_ip_params.src, pkt.get_source());

                ip_params = ip::IpParams {
                    src: lip,
                    dst: dip,
                    ..ip_params
                };
                // let mut mark_tcb_for_deletion = false;
                // let mut sock_to_be_deleted = 0;


                let tcb = &mut (*tcb_ref.write().unwrap());
                // regular socket
                tcb.snd_wnd = pkt_window;
                trace!("snd_wnd = {:?}", tcb.snd_wnd);

                use self::Status::*;
                match tcb.state {
                    Closed => {
                        // Pg. 65 in RFC 793
                        info!("packet recvd on Closed TCB");
                    }
                    Listen => {
                        // Pg. 65-66 in RFC 793
                        debug!("found matching listening socket");
                        // new connection
                        if pkt_flags == TcpFlags::SYN {
                            let mut ntcb = TCB::new(None);
                            ntcb.local_ip = lip;
                            ntcb.local_port = lp;
                            ntcb.remote_ip = dip;
                            ntcb.remote_port = dp;

                            ntcb.rcv_nxt = pkt_seq_num + 1;
                            ntcb.irs = pkt_seq_num;
                            ntcb.snd_wnd = pkt_window;
                            ntcb.snd_nxt = ntcb.iss + 1;
                            ntcb.snd_una = ntcb.iss;
                            ntcb.state = SynRcvd;

                            {
                                let tcp = &mut (*tcp_ctx.write().unwrap());
                                tcp.bound_ports.insert((ntcb.local_ip, ntcb.local_port));
                            }

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
                            tcb.conns_map.insert((dip, dp), ntcb);
                        } else if pkt_flags == TcpFlags::ACK {
                            if let Some(ntcb) = tcb.conns_map.get_mut(&(dip, dp)) {
                                if ntcb.state == SynRcvd {
                                    ntcb.state = Estab;
                                }
                            } else {
                                info!("packet recvd on TCB in Listen State with ACK");
                            }
                            if let Some(ntcb) = tcb.conns_map.remove(&(dip, dp)) {
                                // TODO check for correct ack
                                if let Some(ref qs) = tcb.qs {
                                    if ntcb.state == Estab {
                                        qs.push(ntcb);
                                    }
                                }
                            }
                        } else {
                            info!("pkt recvd in Listen State, but not SYN or ACK (for child)");
                        }
                    }
                    SynSent => {
                        debug!("Handling SynSent");
                        if pkt_flags & TcpFlags::ACK == TcpFlags::ACK {
                            // Pg. 66 in RFC 793
                            if pkt_ack <= tcb.iss || pkt_ack > tcb.snd_nxt {
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
                                tcb.state = Estab;
                                println!("v_connect() returned 0");
                                tcb.connect_resp.push(Ok(()));

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
                                tcb.state = SynRcvd;
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
                        }
                    }
                    _ => {
                        // Otherwise, pg. 69 in RFC 793
                        // TODO discard old dups
                        let seg_len = pkt_size as u32 - 20;
                        trace!("incoming segment length: {}", seg_len);
                        if tcb.rcv_wnd == 0 {
                            if seg_len > 0 {
                                warn!("Dropping pkt, cant accept with 0 window, sending ACK...");
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
                            } else if seg_len == 0 && pkt_seq_num == tcb.rcv_nxt {
                                if tcb.snd_una < pkt_ack && pkt_ack <= tcb.snd_nxt &&
                                   pkt_flags & TcpFlags::ACK == TcpFlags::ACK {
                                    tcb.snd_una = pkt_ack;

                                    // Remove acknowledged segments from retransmit_q
                                    let ack_seq_nums: Vec<_> =
                                        tcb.retransmit_q.keys().cloned().collect();
                                    for seq_num in ack_seq_nums {
                                        if seq_num > tcb.snd_una {
                                            break;
                                        }
                                        tcb.retransmit_q.remove(&seq_num);
                                    }
                                }
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
                            }
                            // tcb.rcv_wnd > 0
                        } else if seg_len == 0 && tcb.rcv_nxt <= pkt_seq_num &&
                                  pkt_seq_num < tcb.rcv_nxt + tcb.rcv_wnd as u32 {
                            if tcb.snd_una < pkt_ack && pkt_ack <= tcb.snd_nxt &&
                               pkt_flags & TcpFlags::ACK == TcpFlags::ACK {
                                tcb.snd_una = pkt_ack;

                                // Remove acknowledged segments from retransmit_q
                                let ack_seq_nums: Vec<_> =
                                    tcb.retransmit_q.keys().cloned().collect();
                                for seq_num in ack_seq_nums {
                                    if seq_num > tcb.snd_una {
                                        break;
                                    }
                                    tcb.retransmit_q.remove(&seq_num);
                                }
                            }
                        } else if seg_len > 0 &&
                                  (tcb.rcv_nxt <= pkt_seq_num &&
                                   pkt_seq_num < tcb.rcv_nxt + tcb.rcv_wnd as u32 ||
                                   tcb.rcv_nxt <= pkt_seq_num + seg_len - 1 &&
                                   pkt_seq_num + seg_len - 1 < tcb.rcv_nxt + tcb.rcv_wnd as u32) {
                            if tcb.rcv_nxt == pkt_seq_num {
                                // ideal case
                                if pkt_flags & TcpFlags::SYN == TcpFlags::SYN {
                                    // Pg. 71 in RFC 793
                                    warn!("received SYN in the window, discarding TCB");
                                    println!("connection reset");
                                    tcb.state = Closed;
                                    {
                                        let tcp = &mut (*tcp_ctx.write().unwrap());
                                        // tcp.tc_blocks.remove(&sock_to_be_deleted).unwrap();
                                        // tcp.free_sockets.push(sock_to_be_deleted);
                                        tcp.bound_ports.remove(&(tcb.local_ip, tcb.local_port));
                                        break;
                                    }
                                }

                                if pkt_flags & TcpFlags::ACK == TcpFlags::ACK {
                                    match tcb.state {
                                        SynRcvd => {
                                            debug!("Handling SynRcvd");
                                            // Pg. 72 in RFC 793
                                            if tcb.snd_una <= pkt_ack && pkt_ack <= tcb.snd_nxt {
                                                tcb.state = Estab;
                                                println!("v_connect() returned 0");
                                                tcb.connect_resp.push(Ok(()));
                                            }
                                        }
                                        Estab | FinWait1 | FinWait2 | CloseWait | Closing => {
                                            if tcb.snd_una < pkt_ack && pkt_ack <= tcb.snd_nxt {
                                                tcb.snd_una = pkt_ack;

                                                // Remove acknowledged segments from retransmit_q
                                                let ack_seq_nums: Vec<_> =
                                                    tcb.retransmit_q.keys().cloned().collect();
                                                for seq_num in ack_seq_nums {
                                                    if seq_num > tcb.snd_una {
                                                        break;
                                                    }
                                                    tcb.retransmit_q.remove(&seq_num);
                                                }

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
                                            } else if pkt_ack > tcb.snd_nxt {
                                                warn!("Dropping segment, rcvd early, sending ACK");
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
                                            }

                                            // TODO more specific processing, see pg. 73
                                            match tcb.state {
                                                // FinWait1 => {}
                                                // FinWait2 => {}
                                                // CloseWait => {}
                                                // Closing => {}
                                                _ => {}
                                            }

                                            // TODO payload processing, see pg. 74
                                            match tcb.state {
                                                Estab | FinWait1 | FinWait2 => {
                                                    // TODO put the received segment in the right
                                                    // place in the buffer
                                                    if tcb.rcv_nxt - tcb.irs + seg_len <=
                                                       tcb.rcv_wnd as u32 {
                                                        debug!("Appending to socket: {:?}, {:?}",
                                                               tcb.remote_ip,
                                                               tcb.remote_port);

                                                        tcb.rcv_buffer
                                                            .copy_from_slice(
                                                                &pkt.payload()[..seg_len as usize]);

                                                        trace!("rcv_buff: {:?}", tcb.rcv_buffer);
                                                        tcb.rcv_wnd -= seg_len as u16;
                                                        debug!("rcv_wnd = {:?}", tcb.rcv_wnd);
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
                                        // LastAck => {}
                                        TimeWait => {
                                            if let Some(ref qs) = tcb.qr {
                                                let qs = qs.clone();
                                                thread::spawn(move || {
                                                    let msl = Duration::from_secs(2 * 60);
                                                    thread::sleep(msl);
                                                    qs.push(Message::Timeout {
                                                        to: TimeoutKind::TimeWaitTO,
                                                    });
                                                });
                                            }
                                        }
                                        _ => {}
                                    }


                                } else {
                                    warn!("Dropping packet, no ACK flag set");
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
        }
        if should_send_packet {
            let seq_num;
            {
                let segment = TcpPacket::new(&pkt_buf[..]).unwrap();
                ip::send(&dl_ctx,
                         Some(&rip_ctx),
                         Some(&tcp_ctx),
                         ip_params.clone(),
                         TCP_PROT,
                         rip::INFINITY,
                         segment.packet().to_vec(),
                         0,
                         true)
                    .unwrap();

                seq_num = segment.get_sequence();
            }
            if ip_params.len > TcpPacket::minimum_packet_size() {
                // segment containing data
                let tcb = &mut (*tcb_ref.write().unwrap());
                tcb.retransmit_q.insert(seq_num,
                                        SegmentIpParams {
                                            pkt_buf: pkt_buf,
                                            params: ip_params,
                                        });
                if let Some(ref qs) = tcb.qr {
                    let qs = qs.clone();
                    thread::spawn(move || {
                        let rto = Duration::from_millis(RTO);
                        thread::sleep(rto);
                        qs.push(Message::Timeout {
                            to: TimeoutKind::Retransmission { seq_num: seq_num },
                        });
                    });
                }
            }
        }
    }
}

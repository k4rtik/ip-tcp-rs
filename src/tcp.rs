use std::net::Ipv4Addr;
use std::collections::{HashMap, HashSet};

enum STATUS {
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

pub struct Socket {
    socket_id: usize,
    local_addr: Ipv4Addr,
    local_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    status: STATUS,
}

struct TCB {
    local_ip: Ipv4Addr,
    local_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    state: STATUS,
}

pub struct TCP {
    // container of TCBs
    tc_blocks: HashMap<usize, TCB>,
    free_sockets: Vec<usize>,
    bound_ports: HashSet<u16>,
}

impl TCP {
    pub fn new() -> TCP {
        debug!("Starting TCP...");
        let tcp = TCP {
            tcb_list: HashMap::new(),
            sockids: HashSet::new(),
        };
        tcp
    }

    pub fn v_socket(&mut self) -> Result<i32, &'static str> {
        debug!("Creating socket...");
        debug!("Initializing TCB...");
        let mut sock_id = 80;
        while true {
            if !self.sockids.contains(&sock_id) {
                break;
            }
            sock_id += 1;
        }
        let mut tcb = TCB {
            socket_id: sock_id,
            local_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            local_port: 0,
            dst_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
            dst_port: 0,
            tcp_state: 0,
        };
        self.tcb_list.insert(sock_id, tcb);
        Ok(sock_id)
    }

    pub fn v_bind(&mut self, socket: i32, addr: Ipv4Addr, port: u16) -> Result<i32, &'static str> {
        debug!("Binding to IP {}, port {}", addr, port);
        self.tcb_list.get_mut(&socket).unwrap().local_ip = addr;
        self.tcb_list.get_mut(&socket).unwrap().local_port = port;
        Ok(0)
    }

    pub fn v_listen(&mut self, socket: i32) -> Result<u32, &'static str> {
        Ok(0)
    }

    pub fn v_connect(&mut self,
                     socket: i32,
                     addr: Ipv4Addr,
                     port: u16)
                     -> Result<i32, &'static str> {
        Ok(0)
    }

    pub fn v_accept(&mut self, socket: i32, addr: Ipv4Addr, port: u16) -> Result<i32, &'static str> {
        let s = self.v_socket();
        if s.is_ok() {
            let sock = s.unwrap();
            let ret = self.v_bind(sock, addr, port);
            if ret.is_ok() {
                let ret = self.v_listen(sock);
            }
        }
        Ok(0)
    }
}

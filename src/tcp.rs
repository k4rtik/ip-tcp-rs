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
        TCP {
            tc_blocks: HashMap::new(),
            free_sockets: Vec::new(),
            bound_ports: HashSet::new(),
        }
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
        match self.tc_blocks.insert(sock_id, tcb) {
            Some(_) => Ok(sock_id),
            None => {
                Err("ENOMEM: Insufficient memory is available. The socket cannot be created until \
                     sufficient resources are freed."
                    .to_owned())
            }
        }
    }

    pub fn v_bind(&mut self, socket: usize, addr: Ipv4Addr, port: u16) -> Result<(), String> {
        info!("Binding to IP {}, port {}", addr, port);
        match self.tc_blocks.get_mut(&socket) {
            Some(tcb) => {
                // TODO check for bound ports
                tcb.local_ip = addr;
                tcb.local_port = port;
                Ok(())
            }
            None => Err("EBADF: sockfd is not a valid descriptor.".to_owned()),
        }
    }

    #[allow(unused_variables)]
    pub fn v_listen(&mut self, socket: usize) -> Result<(), String> {
        Ok(())
    }

    #[allow(unused_variables)]
    pub fn v_connect(&mut self, socket: usize, addr: Ipv4Addr, port: u16) -> Result<usize, String> {
        Ok(0)
    }

    #[allow(unused_variables)]
    pub fn v_accept(&mut self, socket: usize, addr: Ipv4Addr, port: u16) -> Result<usize, String> {
        // XXX TODO Sumukha, this logic goes out in client wrapper for accept command
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

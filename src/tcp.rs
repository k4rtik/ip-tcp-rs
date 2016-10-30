use std::net::Ipv4Addr;

struct TCB {
    local_ip: Ipv4Addr,
    local_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    tcp_state: u16,
}

pub fn v_socket() -> i32 {
    debug!("Creating socket...");
    debug!("Initializing TCB...");
    let mut tcb = TCB {
        local_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
        local_port: 0,
        dst_ip: "0.0.0.0".parse::<Ipv4Addr>().unwrap(),
        dst_port: 0,
        tcp_state: 0,
    };
    1
}

pub fn v_bind(socket: i32, addr: Ipv4Addr, port: u16) -> i32 {
    0
}

pub fn v_listen(socket: i32) -> u32 {
	0
}

pub fn v_connect(socket: i32, addr: Ipv4Addr, port: u16) -> i32 {
	0
}

pub fn v_accept(socket: i32, addr: Ipv4Addr) -> i32 {
	0
}

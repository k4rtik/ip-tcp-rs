extern crate bytes;
extern crate bytes_more;
extern crate clap;
extern crate crossbeam;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;
extern crate pnet;
extern crate pnet_macros_support;
extern crate rand;
extern crate rustyline;

mod datalink;
mod ip;
mod packet;
mod rip;
mod tcp;

use clap::{App, Arg};
use rustyline::error::ReadlineError;
use rustyline::Editor;

use std::fs::File;
use std::io::{BufReader, BufRead};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::io::Read;

use datalink::{DataLink, Interface, SocketAddrInterface, RouteInfo};
use rip::{RipCtx, Route};
use tcp::{Socket, TCP};

fn parse_lnx(filename: &str) -> RouteInfo {
    let mut file = BufReader::new(File::open(filename).unwrap());

    let mut myinfo = String::new();
    file.read_line(&mut myinfo).expect("Parse error: couldn't read self information");

    let socket_addr = myinfo.trim().to_string();
    let mut _id = 0;
    let interfaces: Vec<_> = file.lines()
        .map(|line| {
            let line = line.unwrap();
            let line_vec: Vec<&str> = line.split(' ').collect();
            SocketAddrInterface {
                to_socket_addr: line_vec[0].to_string(),
                src_vip: line_vec[1].parse::<Ipv4Addr>().unwrap(),
                dst_vip: line_vec[2].parse::<Ipv4Addr>().unwrap(),
            }
        })
        .collect();

    trace!("{:?}", socket_addr);
    trace!("{:?}", interfaces);

    RouteInfo {
        socket_addr: socket_addr,
        interfaces: interfaces,
    }
}

fn print_interfaces(interfaces: Vec<Interface>) {
    println!("id\tdst\t\tsrc\t\tenabled");
    for (i, iface) in interfaces.iter().enumerate() {
        println!("{}\t{}\t{}\t{}", i, iface.dst, iface.src, iface.enabled);
    }
}

fn print_routes(routes: Vec<Route>) {
    if !routes.is_empty() {
        println!("dst\t\tsrc\t\tcost");
        for r in routes {
            if r.cost < rip::INFINITY {
                println!("{}\t{}\t{}", r.dst, r.src, r.cost);
            } else {
                info!("{}\t{}\t{}", r.dst, r.src, r.cost);
            }
        }
    } else {
        println!("No routes found!");
    }
}

fn print_sockets(sockets: Vec<Socket>) {
    println!("socket\tlocal-addr\tport\tdst-addr\tport\tstatus");
    for s in sockets {
        if s.dst_port != 0 {
            println!("{}\t{}\t{}\t{}\t{}\t{:?}",
                     s.socket_id,
                     s.local_addr,
                     s.local_port,
                     s.dst_addr,
                     s.dst_port,
                     s.status);
        } else {
            println!("{}\t{}\t{}\t{}\t\t{}\t{:?}",
                     s.socket_id,
                     s.local_addr,
                     s.local_port,
                     s.dst_addr,
                     s.dst_port,
                     s.status);
        }
    }
}


pub fn print_window_sz(tcp_ctx: &Arc<RwLock<TCP>>, sock: usize) {
    let tcp = &mut (*tcp_ctx.write().unwrap());
    if let Ok(sz) = tcp.get_snd_wnd_sz(sock) {
        println!("Send Window Size: {}", sz);
    }
    if let Ok(sz) = tcp.get_rcv_wnd_sz(sock) {
        println!("Recv Window Size: {}", sz);
    }
}

pub fn accept_cmd(tcp_ctx: &Arc<RwLock<TCP>>,
                  dl_ctx: &Arc<RwLock<DataLink>>,
                  rip_ctx: &Arc<RwLock<RipCtx>>,
                  port: u16) {
    let s = tcp::v_socket(tcp_ctx, dl_ctx, rip_ctx);
    {
        let tcp = &mut (*tcp_ctx.write().unwrap());
        match s {
            Ok(ref sock) => {
                match tcp.v_bind(dl_ctx, *sock, None, port) {
                    Ok(_) => {
                        match tcp.v_listen(dl_ctx, *sock) {
                            Ok(_) => trace!("v_listen() succeeded"),
                            Err(e) => error!("v_listen: {}", e),
                        }
                    }

                    Err(e) => error!("v_bind: {}", e),
                }
            }
            Err(ref e) => error!("v_socket: {}", e),
        }
    }
    let sock = s.unwrap();
    let dl_ctx = dl_ctx.clone();
    let rip_ctx = rip_ctx.clone();
    let tcp_ctx = tcp_ctx.clone();
    thread::spawn(move || {
        loop {
            match tcp::v_accept(tcp_ctx.clone(), dl_ctx.clone(), rip_ctx.clone(), sock, None) {
                Ok(socket) => println!("v_accept on {} returned {}", sock, socket),
                Err(e) => error!("v_accept: {}", e),
            }
        }
    });
}

pub fn connect_cmd(tcp_ctx: &Arc<RwLock<TCP>>,
                   dl_ctx: &Arc<RwLock<DataLink>>,
                   rip_ctx: &Arc<RwLock<RipCtx>>,
                   addr: Ipv4Addr,
                   port: u16) {
    let s = tcp::v_socket(tcp_ctx, dl_ctx, rip_ctx);
    match s {
        Ok(sock) => {
            match tcp::v_connect(tcp_ctx, rip_ctx, sock, addr, port) {
                Ok(_) => info!("v_connect() put new TCB in SynSent state"),
                Err(e) => error!("v_connect() failed: {}", e),
            }
        }
        Err(e) => error!("v_socket() failed: {}", e),
    }
}

pub fn send_cmd(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, message: String) {
    let bytes = tcp::v_write(tcp_ctx, socket, message.as_bytes());
    debug!("bytes written: {:?}", bytes);
}

pub fn send_file_cmd(tcp_ctx: &Arc<RwLock<TCP>>,
                     dl_ctx: &Arc<RwLock<DataLink>>,
                     rip_ctx: &Arc<RwLock<RipCtx>>,
                     fl: String,
                     addr: Ipv4Addr,
                     port: u16) {
    info!("Sending file...");
    let s = tcp::v_socket(tcp_ctx, dl_ctx, rip_ctx);
    match s {
        Ok(sock) => {
            match tcp::v_connect(tcp_ctx, rip_ctx, sock, addr, port) {
                Ok(_) => {
                    info!("v_connect() put new TCB in SynSent state");
                    let mut f = BufReader::new(File::open(fl).unwrap());
                    let mut buf = vec![0; 1024];
                    while let Ok(bytes_read) = f.read(&mut buf) {
                        if bytes_read == 0 {
                            break;
                        }
                        trace!("buf: {:?}", buf);
                        let bytes = tcp::v_write(tcp_ctx, sock, &buf[..bytes_read]);
                        trace!("bytes written: {:?}", bytes);
                    }
                    tcp::v_close(tcp_ctx, sock).unwrap();
                }
                Err(e) => error!("v_connect() failed: {}", e),
            }
        }
        Err(e) => error!("v_socket() failed: {}", e),
    }

}

pub fn recv_cmd(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, size: usize, block: bool) {
    info!("Receiving...");
    info!("Size req: {:?}", size);
    let mut data_recv = Vec::new();
    if block {
        loop {
            match tcp::v_read(tcp_ctx, socket, size - data_recv.len()) {
                Ok(mut data) => {
                    data_recv.append(&mut data);
                    if data_recv.len() >= size {
                        debug!("bytes written: {:?}", data_recv.len());
                        break;
                    }
                } 
                Err(e) => println!("{:?}", e),
            }
        }
    } else {
        match tcp::v_read(tcp_ctx, socket, size) {
            Ok(mut data) => {
                data_recv.append(&mut data);
            }
            Err(e) => println!("{:?}", e),
        }
    }
    debug!("Data recvd: {:?}", String::from_utf8_lossy(&data_recv));
    debug!("bytes written: {:?}", data_recv.len());
}

fn shutdown_cmd(tcp_ctx: &Arc<RwLock<TCP>>, socket: usize, mode: String) {
    info!("Shutting down...");
    let m = if mode == "read" {
        2
    } else if mode == "both" {
        3
    } else {
        1 // write
    };
    match tcp::v_shutdown(tcp_ctx, socket, m) {
        Ok(_) => println!("Shutdown successful!"),
        Err(e) => println!("Shutdown failed! {:?}", e),
    }
}

#[allow(unknown_lints)]
#[allow(cyclomatic_complexity)]
fn cli_impl(dl_ctx: Arc<RwLock<DataLink>>,
            rip_ctx: Arc<RwLock<RipCtx>>,
            tcp_ctx: Arc<RwLock<TCP>>) {
    let mut rl = Editor::<()>::new();
    if rl.load_history("history.txt").is_err() {
        warn!("No previous history.");
    }
    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(cmd) => {
                rl.add_history_entry(&cmd);
                let cmd_split = cmd.trim().split(' ');
                let cmd_vec = cmd_split.collect::<Vec<&str>>();
                match cmd_vec[0] {
                    "interfaces" | "li" => {
                        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
                        print_interfaces(interfaces);
                    }
                    "routes" | "lr" => {
                        let routes = (*rip_ctx.read().unwrap()).get_routes(None);
                        print_routes(routes);
                    }
                    "sockets" | "ls" => {
                        let mut sockets = (*tcp_ctx.read().unwrap()).get_sockets();
                        sockets.sort_by_key(|s| s.socket_id);
                        print_sockets(sockets);
                    }
                    "accept" | "a" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing port number!");
                        } else {
                            let port = cmd_vec[1].parse::<u16>();
                            match port {
                                Ok(port) => accept_cmd(&tcp_ctx, &dl_ctx, &rip_ctx, port),
                                Err(e) => println!("Error {}", e),
                            }

                        }
                    }
                    "connect" | "c" => {
                        if cmd_vec.len() != 3 {
                            println!("Missing parameters!");
                        } else {
                            let addr = cmd_vec[1].parse::<Ipv4Addr>();
                            match addr {
                                Ok(addr) => {
                                    let port = cmd_vec[2].parse::<u16>();
                                    match port {
                                        Ok(port) => {
                                            connect_cmd(&tcp_ctx, &dl_ctx, &rip_ctx, addr, port);
                                        }
                                        Err(e) => println!("Port value not in format! \n {}", e),
                                    }

                                }
                                Err(e) => println!("IP Address not in format! \n {}", e),
                            }
                        }
                    }
                    "down" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing interface id!");
                        } else {
                            let id = cmd_vec[1].parse::<usize>();
                            match id {
                                Ok(id) => {
                                    debug!("Taking read lock on DataLink");
                                    if (*dl_ctx.write().unwrap()).deactivate_interface(id) {
                                        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
                                        debug!("Taking write lock on RipCtx");
                                        (*rip_ctx.write().unwrap())
                                            .toggle_interface_state(&dl_ctx,
                                                                    interfaces[id].src,
                                                                    false);
                                        debug!("Took interface down");
                                    }
                                }
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                    }
                    "up" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing interface id!");
                        } else {
                            let id = cmd_vec[1].parse::<usize>();
                            match id {
                                Ok(id) => {
                                    debug!("Taking read lock on DataLink");
                                    if (*dl_ctx.write().unwrap()).activate_interface(id) {
                                        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
                                        debug!("Taking write lock on RipCtx");
                                        (*rip_ctx.write().unwrap())
                                            .toggle_interface_state(&dl_ctx,
                                                                    interfaces[id].src,
                                                                    true);
                                        debug!("Took interface up");
                                    }
                                }
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                    }
                    "send" | "s" | "w" => {
                        // TODO this implementation is for IP, write one for TCP
                        if cmd_vec.len() < 3 {
                            println!("Missing parameters");
                        } else {
                            let socket = cmd_vec[1].parse::<usize>().unwrap();
                            let string = cmd_vec[2];
                            let message = string.to_string();
                            send_cmd(&tcp_ctx, socket, message);
                        }
                    }
                    "recv" | "r" => {
                        if cmd_vec.len() > 4 {
                            println!("Unknown parameters!");
                        } else {
                            let socket = cmd_vec[1].parse::<usize>().unwrap();
                            let size = cmd_vec[2].parse::<usize>().unwrap();
                            if cmd_vec.len() == 4 {
                                if cmd_vec[3] == "y" {
                                    recv_cmd(&tcp_ctx, socket, size, true);
                                } else {
                                    recv_cmd(&tcp_ctx, socket, size, false);
                                }
                            } else {
                                recv_cmd(&tcp_ctx, socket, size, false);
                            }
                        }
                    }
                    "sendfile" | "sf" => {
                        if cmd_vec.len() != 4 {
                            println!("Missing parameters!");
                        } else {
                            let file_name = cmd_vec[1].to_string();
                            match cmd_vec[2].parse::<Ipv4Addr>() {
                                Ok(ip) => {
                                    let port = cmd_vec[3].parse::<u16>().unwrap();
                                    send_file_cmd(&tcp_ctx, &dl_ctx, &rip_ctx, file_name, ip, port);
                                }
                                Err(_) => println!("IP address not in format!"),
                            }
                        }
                    }
                    "recvfile" | "rf" => {
                        if cmd_vec.len() != 3 {
                            println!("Missing parameters!");
                        } else {
                            println!("Receiving file...");
                        }
                    }
                    "window" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing socket number!");
                        } else {
                            let socket = cmd_vec[1].parse::<usize>().unwrap();
                            print_window_sz(&tcp_ctx, socket);
                        }
                    }
                    "shutdown" => {
                        if cmd_vec.len() < 2 {
                            println!("Missing parameters!");
                        } else {
                            let socket = cmd_vec[1].parse::<usize>().unwrap();
                            if cmd_vec.len() == 3 {
                                let mode = cmd_vec[2].parse::<String>().unwrap();
                                shutdown_cmd(&tcp_ctx, socket, mode);
                            } else {
                                shutdown_cmd(&tcp_ctx, socket, "write".to_string());
                            }
                        }
                    }
                    "close" => {
                        if cmd_vec.len() != 2 {
                            println!("syntax error (usage: close <socket>)");
                        } else {
                            println!("Closing socket...");
                            let socket = cmd_vec[1].parse::<usize>().unwrap();
                            match tcp::v_close(&tcp_ctx, socket) {
                                Ok(_) => println!("v_close() returned 0"),
                                Err(e) => println!("v_close() error: {:?}", e),
                            }
                        }
                    }
                    "help" => {
                        println!("Commands:
interfaces/li                       - list interfaces
routes/lr                           - list routing table rows
sockets/ls                          - list sockets (fd, ip, port, state)
down <id>                           - disable interface with id
up <id>                             - enable interface with id
accept/a <port>                     - start listening for incoming connections on the specified port
connect/c <ip> <port>               - attempt to connect to the specified IP address:port
send/s/w <socket> <data>            - send a string on a socket
recv/r <socket> <numbytes> <y/n>    - receive numbytes from socket, blocking if y, n is default
sendfile/sf <file> <ip> <port>      - send given file to ip:port
recvfile/rf <file> <port>           - listens on given port and writes output to specified file
window <socket>                     - lists window sizes for socket
shutdown <socket> <read/write/both> - v_shutdown on the given socket
close <socket>                      - v_close on the given socket
help                                - show this help");
                    }
                    "" => {}
                    _ => {
                        println!("invalid command, see \"help\"");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                info!("Ctrl-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                info!("Ctrl-D");
                break;
            }
            Err(err) => {
                error!("Error: {:?}", err);
                break;
            }
        }
    }
    rl.save_history("history.txt").unwrap();
    info!("CLI loop exited");
    std::process::exit(0);
}

fn main() {
    pretty_env_logger::init();

    let matches = App::new("node")
        .version("0.1.0")
        .arg(Arg::with_name("lnx file").required(true).index(1).help("e.g.: A.lnx"))
        .get_matches();

    let lnx_file = matches.value_of("lnx file").unwrap().parse::<String>().unwrap();

    let ri = parse_lnx(&lnx_file);

    let (datalink, dl_rx) = DataLink::new(&ri);
    let dl_ctx = Arc::new(RwLock::new(datalink));

    let rip_ctx = Arc::new(RwLock::new(RipCtx::new(&ri)));

    let tcp_ctx: &Arc<RwLock<TCP>> = &Arc::new(RwLock::new(TCP::new()));

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    let tcp_ctx_clone = tcp_ctx.clone();

    println!("Starting node...");
    thread::spawn(move || cli_impl(dl_ctx_clone, rip_ctx_clone, tcp_ctx_clone));

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    thread::spawn(move || rip::start_rip_module(&dl_ctx_clone, &rip_ctx_clone));

    ip::start_ip_module(&dl_ctx, &rip_ctx, tcp_ctx, dl_rx);
}

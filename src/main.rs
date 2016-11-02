extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate pnet;
extern crate pnet_macros_support;
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
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;

use datalink::*;
use rip::*;
use tcp::*;

fn parse_lnx(filename: &str) -> RouteInfo {
    let mut file = BufReader::new(File::open(filename).unwrap());

    let mut myinfo = String::new();
    file.read_line(&mut myinfo).expect("Parse error: couldn't read self information");

    // TODO validate socket_addr
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

fn is_ip(ip_addr: &str) -> bool {
    match Ipv4Addr::from_str(ip_addr) {
        Ok(_) => true,
        Err(_) => {
            trace!("{:?}", ip_addr);
            false
        }
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

#[allow(unused_variables)]
fn cli_impl(dl_ctx: Arc<RwLock<DataLink>>,
            rip_ctx: Arc<RwLock<RipCtx>>,
            tcp_ctx: Arc<RwLock<TCP>>) {
    let mut rl = Editor::<()>::new();
    if let Err(_) = rl.load_history("history.txt") {
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
                        let routes = (*rip_ctx.read().unwrap()).get_routes();
                        print_routes(routes);
                    }
                    "sockets" | "ls" => {
                        println!("Printing Sockets!");
                    }
                    "accept" | "a" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing port number!");
                        } else {
                            let port = cmd_vec[1].parse::<u16>();
                            match port {
                                Ok(port) => (*tcp_ctx.write().unwrap()).accept_cmd(port),
                                Err(e) => println!("Error {}", e),
                            }

                        }
                    }

                    "connect" | "c" => {
                        if cmd_vec.len() != 3 {
                            println!("Missing parameters!");
                        } else {
                            println!("Connecting...");
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
                    "send" => {
                        if cmd_vec.len() != 4 {
                            println!("Missing parameters");
                        } else if !is_ip(cmd_vec[1]) {
                            println!("IP address is not in format!");
                        } else {
                            let dest_ip = cmd_vec[1].parse::<Ipv4Addr>().unwrap();
                            let proto = cmd_vec[2].parse::<u8>().unwrap();
                            let string = cmd_vec[3];
                            let message = string.to_string().into_bytes();
                            let ip_params = ip::IpParams {
                                src: Ipv4Addr::new(127, 0, 0, 1),
                                dst: dest_ip,
                                len: message.len(),
                                tos: 0,
                                opt: vec![],
                            };
                            let res = ip::send(&dl_ctx,
                                               Some(&rip_ctx),
                                               ip_params,
                                               proto,
                                               rip::INFINITY,
                                               message,
                                               0,
                                               true);
                            match res {
                                Ok(_) => info!("Message sent succesfully"),
                                Err(str) => warn!("{}", str),
                            }
                        }
                    }
                    "help" => {
                        println!("- help: Print this list of commands.\n
- interfaces: Print \
                                  information about each interface, one per line.\n
- routes: \
                                  Print information about the route to each known destination, \
                                  one per line.\n
- sockets: List all sockets, along with the \
                                  state the TCP connection associated with them is in, and their \
                                  current window sizes.\n
- down [integer]: Bring an interface \
                                  \"down\".\n
- up [integer]: Bring an interface \"up\" (it must \
                                  be an existing interface, probably one you brought down)\n
- \
                                  accept [port]: Spawn a socket, bind it to the given port, and \
                                  start accepting connections on that port.\n
- connect [ip] \
                                  [port]: Attempt to connect to the given ip address, in dot \
                                  notation, on the given port.  send [socket] [data]: Send a \
                                  string on a socket.\n
- recv [socket] [numbytes] [y/n]: Try to \
                                  read data from a given socket. If the last argument is y, then \
                                  you should block until numbytes is received, or the connection \
                                  closes. If n, then don.t block; return whatever recv returns. \
                                  Default is n.\n
- sendfile [filename] [ip] [port]: Connect to \
                                  the given ip and port, send the entirety of the specified \
                                  file, and close the connection.\n
- recvfile [filename] \
                                  [port]: Listen for a connection on the given port. Once \
                                  established, write everything you can read from the socket to \
                                  the given file. Once the other side closes the connection, \
                                  close the connection as well.\n
- shutdown [socket] \
                                  [read/write/both]: v_shutdown on the given socket. If read is \
                                  given, close only the reading side. If write is given, close \
                                  only the writing side. If both is given, close both sides. \
                                  Default is write.\n
- close [socket]: v_close on the given \
                                  socket.\n");
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
    env_logger::init().expect("Failed to initialize logger");

    let matches = App::new("node")
        .version("0.1.0")
        .arg(Arg::with_name("lnx file").required(true).index(1).help("e.g.: A.lnx"))
        .get_matches();

    let lnx_file = matches.value_of("lnx file").unwrap().parse::<String>().unwrap();

    let ri = parse_lnx(&lnx_file);

    let (datalink, dl_rx) = DataLink::new(&ri);
    let dl_ctx = Arc::new(RwLock::new(datalink));

    let rip_ctx = Arc::new(RwLock::new(RipCtx::new(&ri)));

    let tcp_ctx = Arc::new(RwLock::new(TCP::new()));

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    let tcp_ctx_clone = tcp_ctx.clone();

    println!("Starting node...");
    thread::spawn(move || cli_impl(dl_ctx_clone, rip_ctx_clone, tcp_ctx_clone));

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    thread::spawn(move || rip::start_rip_module(&dl_ctx_clone, &rip_ctx_clone));

    ip::start_ip_module(&dl_ctx, &rip_ctx, dl_rx); //, &tcp_ctx);
}

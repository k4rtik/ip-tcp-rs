extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate pnet;
extern crate pnet_macros_support;

mod datalink;
mod ip;
mod packet;
mod rip;

use clap::{App, Arg};

use std::fs::File;
use std::io::{self, BufReader, BufRead, Write};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;

use datalink::*;
use rip::RipCtx;

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

fn cli_impl(dl_ctx: Arc<RwLock<DataLink>>, rip_ctx: Arc<RwLock<RipCtx>>) {
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let cmd = &mut String::new();
        match io::stdin().read_line(cmd) {
            Ok(0) => {
                info!("EndOfFile sent (Ctrl-D)");
                break;
            }
            Ok(_) => {
                let cmd_split = cmd.trim().split(' ');
                let cmd_vec = cmd_split.collect::<Vec<&str>>();
                match cmd_vec[0] {
                    "interfaces" => {
                        println!("id\tdst\t\tsrc\t\tenabled");
                        let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
                        for (i, iface) in interfaces.iter().enumerate() {
                            println!("{}\t{}\t{}\t{}", i, iface.dst, iface.src, iface.enabled);
                        }
                    }
                    "routes" => {
                        let routes = (*rip_ctx.read().unwrap()).get_routes();
                        if !routes.is_empty() {
                            println!("dst\t\tsrc\t\tcost");
                            for r in routes {
                                if r.cost < rip::INFINITY {
                                    println!("{}\t{}\t{}", r.dst, r.src, r.cost);
                                }
                            }
                        } else {
                            println!("No routes found!");
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
                                    (*dl_ctx.read().unwrap()).deactivate_interface(id);
                                    let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
                                    debug!("Taking write lock on RipCtx");
                                    (*rip_ctx.write().unwrap())
                                        .toggle_interface_state(&dl_ctx, interfaces[id].src, false);
                                    debug!("Took interface down");
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
                                    (*dl_ctx.read().unwrap()).activate_interface(id);
                                    let interfaces = (*dl_ctx.read().unwrap()).get_interfaces();
                                    debug!("Taking write lock on RipCtx");
                                    (*rip_ctx.write().unwrap())
                                        .toggle_interface_state(&dl_ctx, interfaces[id].src, true);
                                    debug!("Took interface up");
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
                        println!("Commands:
up <id>                         - enable interface with id
down <id>                       - disable interface with id
send <dst_ip> <prot> <payload>  - send ip packet to <dst_ip> using prot <prot>
interfaces                      - list interfaces
routes                          - list routing table rows
help                            - show this help");
                    }
                    "" => {}
                    _ => {
                        println!("invalid command, see \"help\"");
                    }
                }
            }
            Err(_) => {
                panic!("Unexpected error reading from stdin");
            }
        }
    }
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

    let (datalink, rx) = DataLink::new(&ri);
    let dl_ctx = Arc::new(RwLock::new(datalink));

    let rip_ctx = Arc::new(RwLock::new(RipCtx::new(&ri)));

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    println!("Starting node...");
    thread::spawn(move || cli_impl(dl_ctx_clone, rip_ctx_clone));

    let dl_ctx_clone = dl_ctx.clone();
    let rip_ctx_clone = rip_ctx.clone();
    thread::spawn(move || rip::start_rip_module(&dl_ctx_clone, &rip_ctx_clone));

    ip::start_ip_module(&dl_ctx, &rip_ctx, rx);

}

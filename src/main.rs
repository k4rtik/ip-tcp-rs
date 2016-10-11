#[macro_use]
extern crate log;

extern crate clap;
extern crate env_logger;
extern crate pnet;

use clap::{App, Arg};

use std::fs::File;
use std::io::{self, BufReader, BufRead, Write};
use std::net::Ipv4Addr;
use std::str::FromStr;

mod datalink;
use datalink::*;

mod ip;
mod rip;

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

    debug!("{:?}", socket_addr);
    debug!("{:?}", interfaces);

    RouteInfo {
        socket_addr: socket_addr,
        interfaces: interfaces,
    }
}

fn is_ip(ip_addr: &str) -> bool {
    match Ipv4Addr::from_str(ip_addr) {
        Ok(_) => true,
        Err(_) => {
            debug!("{:?}", ip_addr);
            false
        }
    }
}

fn cli_impl(datalink: &DataLink) {
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
                        println!("id\tsource\t\tdestination\tstatus");
                        for (i, iface) in datalink.get_interfaces().iter().enumerate() {
                            println!("{}\t{}\t{}\t{}", i, iface.src, iface.dst, iface.enabled);
                        }
                    }
                    "routes" => {
                        println!("routes recongnized!");
                    }
                    "down" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing interface number!");
                        } else {
                            let tmp = cmd_vec[1].parse::<usize>();
                            match tmp {
                                Ok(interface) => {
                                    datalink.deactivate_interface(interface);
                                }
                                Err(_) => println!("Please mention the interface number!"),
                            }
                        }
                    }
                    "up" => {
                        if cmd_vec.len() != 2 {
                            println!("Missing interface number!");
                        } else {
                            let tmp = cmd_vec[1].parse::<usize>();
                            match tmp {
                                Ok(interface) => {
                                    datalink.activate_interface(interface);
                                }
                                Err(_) => println!("Please mention the interface number!"),
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
                            let mut payload = string.to_string().into_bytes();
                            let payload_len = payload.len();
                            if ip::send_message(datalink,
                                                dest_ip,
                                                &mut payload,
                                                payload_len,
                                                proto) {
                                info!("Message sent succesfully");
                            } else {
                                error!("Message sending failed!");
                            }
                        }
                    }
                    "shutdown" => {
                        println!("shutting down node...");
                        break;
                    }
                    _ => {
                        println!("Invalid command!");
                    }
                }
            }
            Err(_) => {
                panic!("Unexpected error reading from stdin");
            }
        }
    }
}

fn main() {
    env_logger::init().expect("Failed to initialize logger");

    let matches = App::new("node")
        .version("0.1.0")
        .arg(Arg::with_name("lnx file").required(true).index(1).help("e.g.: A.lnx"))
        .get_matches();

    let lnx_file = matches.value_of("lnx file").unwrap().parse::<String>().unwrap();

    let ri = parse_lnx(&lnx_file);

    let (datalink, rx) = DataLink::new(ri);
    ip::start_ip_module(&datalink, rx);

    // TODO need to remove dependency of passing datalink to cli (to spawn a separate thread)
    println!("Starting node...");
    cli_impl(&datalink);
}

use std::io;
use std::thread;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate clap;

use clap::{App, Arg};


struct RouteInfo {
    self_ip: String,
    self_port: i32,
    interfaces: Vec<Interface>,
}

struct Interface {
    ip: String,
    port: i32,
    vip: String,
    to_ip: String,
}


fn parse_lnx(contents: &str) -> RouteInfo {
    let content = &mut String::new();
    content.push_str(contents);
    let content_split_vec = content.trim().split('\n').collect::<Vec<&str>>();
    let mut tmp = content_split_vec[0].split(':').collect::<Vec<&str>>();
    let s_ip = String::from(tmp[0]);
    let s_port = i32::from_str(tmp[1]).unwrap();
    let mut ifaces = Vec::<Interface>::new();
    println!("{}", content_split_vec.len());
    for idx in 1..content_split_vec.len() {
        tmp = content_split_vec[idx].split(' ').collect::<Vec<&str>>();
        let i = Interface {
            ip: String::from(tmp[0].split(':').collect::<Vec<&str>>()[0]),
            port: i32::from_str(tmp[0].split(':').collect::<Vec<&str>>()[1]).unwrap(),
            vip: String::from(tmp[1]),
            to_ip: String::from(tmp[2]),
        };
        ifaces.push(i);
    }
    println!("{}", ifaces[0].ip);
    let ri = RouteInfo {
        self_ip: s_ip,
        self_port: s_port,
        interfaces: ifaces,
    };
    println!("{}, {}, {}",
             ri.self_ip,
             ri.self_port,
             ri.interfaces[0].to_ip);
    return ri;
}

// TODO this can be replaced with from_str() for std::net::Ipv4Addr
fn is_ip(ip_addr: &str) -> bool {
    let mut idx = 0;
    let ip = &mut String::new();
    ip.push_str(ip_addr);
    let ip_split = ip.split('.');
    for i in ip_split {
        let part = i.parse::<i32>();
        match part {
            Ok(tmp) => {
                if tmp < 0 || tmp > 255 {
                    return false;
                }
            }
            Err(_) => {
                println!("IP address not in format!");
                return false;
            }
        }
        idx += 1;
        if idx > 4 {
            println!("IP address is longer than expected!");
            return false;
        }
    }
    return true;
}

fn cli_impl() {
    let stdin = io::stdin();
    let cmd = &mut String::new();
    loop {
        cmd.clear();
        stdin.read_line(cmd).unwrap();
        let cmd_split = cmd.trim().split(' ');
        let cmd_vec = cmd_split.collect::<Vec<&str>>();
        match &cmd_vec[0] as &str {
            "interfaces" => {
                println!("interfaces recongnized!");
            }
            "routes" => {
                println!("routes recongnized!");
            }
            "down" => {
                if cmd_vec.len() != 2 {
                    println!("Missing interface number!");
                } else {
                    let tmp = cmd_vec[1].parse::<i32>();
                    match tmp {
                        Ok(interface) => println!("Interface: {}", interface),
                        Err(_) => println!("Please mention the interface number!"),
                    }
                }
            }
            "up" => {
                if cmd_vec.len() != 2 {
                    println!("Missing interface number!");
                } else {
                    let tmp = cmd_vec[1].parse::<i32>();
                    match tmp {
                        Ok(interface) => println!("Interface: {}", interface),
                        Err(_) => println!("Please mention the interface number!"),
                    }
                }
            }
            "send" => {
                if cmd_vec.len() != 4 {
                    println!("Missing parameters");
                } else {
                    if is_ip(cmd_vec[1]) == false {
                        println!("IP address is not in format!");
                    }
                }
            }
            "shutdown" => {
                println!("shutting down node...");
                return;
            }
            _ => {
                println!("Invalid command!");
            }
        }
    }
}

fn main() {
    env_logger::init().ok().expect("Failed to initialize logger");

    let matches = App::new("node")
        .version("0.1.0")
        .arg(Arg::with_name("lnx file").required(true).index(1).help("e.g.: A.lnx"))
        .get_matches();

    let lnx_file = matches.value_of("lnx file").unwrap().parse::<String>().unwrap();
    let mut file = match File::open(lnx_file) {
        Err(_) => panic!("couldn't open the lnx file!"),
        Ok(file) => file,
    };

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Err(_) => panic!("couldn't read the file!"),
        Ok(_) => print!("{}", contents),
    }

    let ri = parse_lnx(&contents);

    let child = thread::spawn(move || {
        println!("Starting node...");
        cli_impl();
    });
    child.join().unwrap();
}

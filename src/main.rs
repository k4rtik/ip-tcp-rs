use std::io;
use std::thread;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

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
    let args: Vec<_> = env::args().collect();
    let lnx_file_path = Path::new(&args[1]);
    let mut file = match File::open(&lnx_file_path) {
        Err(_) => panic!("couldn't open the lnx file!"),
        Ok(file) => file,
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Err(_) => panic!("couldn't read the file!"),
        Ok(_) => print!("{}", contents),
    }
    let child = thread::spawn(move || {
        println!("Starting node...");
        cli_impl();
    });
    child.join().unwrap();
}

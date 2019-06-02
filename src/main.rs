#[macro_use]
extern crate log;

use clap::{Arg, App};
use simplelog::*;
use std::fs::File;
use std::thread;
use std::sync::mpsc;

mod db {
    pub mod sqlite3;
}

mod net {
    pub mod arp;
}

// List all interfaces.
fn list_interfaces() -> Vec<String> {
    let mut ifaces: Vec<String> = Vec::new();
    for iface in get_if_addrs::get_if_addrs().unwrap() {
        ifaces.push(iface.name);
    }
    ifaces.sort();
    ifaces.dedup();
    ifaces
}

fn main() {
    let interfaces = list_interfaces();

    let mut values: Vec<&str> = Vec::new();
    for value in interfaces.iter() {
        values.push(&value[..]);
    }

    // Using clap to parse and validate command line arguments. https://docs.rs/clap/
    let matches = App::new("Netgrasp")
        .version("0.10.0")
        .author("Jeremy Andrews <jeremy@tag1consulting.com>")
        .about("A passive network observation tool")
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Specify the network interface to listen on")
            .possible_values(&values)
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("logfile")
            .short("l")
            .long("logfile")
            .value_name("LOGFILE")
            .help("Path of logfile (default './netgrasp.log')")
            .takes_value(true))
        .arg(Arg::with_name("g")
            .short("g")
            .multiple(true)
            .help("Sets the logged level of verbosity"))
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the output level of verbosity"))
        .get_matches();

    // Allow optionally controlling debug output level
    let debug_level;
    match matches.occurrences_of("v") {
        0 => debug_level = LevelFilter::Warn,
        1 => debug_level = LevelFilter::Info,
        2 => debug_level = LevelFilter::Debug,
        3 | _ => debug_level = LevelFilter::Trace,
    }

    let log_level;
    match matches.occurrences_of("g") {
        0 => log_level = LevelFilter::Warn,
        1 => log_level = LevelFilter::Info,
        2 => log_level = LevelFilter::Debug,
        3 | _ => log_level = LevelFilter::Trace,
    }

    // @TODO: confirm that the path exists and is writeable
    let log_file = matches.value_of("logfile").unwrap_or("./netgrasp.log");
    
    CombinedLogger::init(
        vec![
            TermLogger::new(debug_level, Config::default()).unwrap(),
            WriteLogger::new(log_level, Config::default(), File::create(log_file).unwrap()),
        ]
    ).unwrap();
    info!("Output verbosity level: {}", debug_level);
    info!("Logfile verbosity level: {}", log_level);
    info!("Writing to log file: {}", log_file);
    debug!("Available interfaces: {:?}", interfaces);

    // We require an interface so unwrap() is safe here.
    let interface = matches.value_of("interface").unwrap();
    let iface: String = interface.to_string();
    info!("Listening interface: {}", iface);

    // Create a thread for monitoring ARP packets.
    let (arp_tx, arp_rx) = mpsc::channel();
    thread::spawn(move || {
        net::arp::listen(iface, arp_tx);
    });

    db::sqlite3::create_database();

    loop {
        let received = arp_rx.recv().unwrap();
        //println!("{}: ARP {:?} packet from {} {} targeting {} {}", 
        //    received.interface, received.operation,
        //    received.src_ip.to_string(), received.src_mac.to_string(),
        //    received.tgt_ip.to_string(), received.tgt_mac.to_string());
        db::sqlite3::log_arp_packet(received);
    }
}

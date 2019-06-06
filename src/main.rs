#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

use clap::{Arg, App};
use simplelog::*;
use std::fs::File;
use std::thread;
use std::sync::mpsc;
use std::path::PathBuf;
use std::fs;
pub mod statics;
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
            .value_name("LOG FILE")
            .help("Path of logfile")
            .takes_value(true))
        .arg(Arg::with_name("dbfile")
            .short("d")
            .long("dbfile")
            .value_name("DATABASE FILE")
            .help("Path of database file")
            .takes_value(true))
        .arg(Arg::with_name("update")
            .short("u")
            .long("update")
            .help("Update MAC addresses vendor db"))
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

    let mut log_file;
    match matches.value_of("logfile") {
        None => {
            let data_local_dir = statics::PROJECT_DIRS.data_local_dir();
            log_file = PathBuf::new();
            log_file.push(data_local_dir);
            log_file.push("netgrasp.log");
        }
        _ => {
            log_file = PathBuf::from(matches.value_of("logfile").unwrap());
        }
    }
    fs::create_dir_all(&log_file.parent().unwrap()).expect("Failed to create log file.");
    
    CombinedLogger::init(
        vec![
            TermLogger::new(debug_level, Config::default()).unwrap(),
            WriteLogger::new(log_level, Config::default(), File::create(&log_file).unwrap()),
        ]
    ).unwrap();
    info!("Output verbosity level: {}", debug_level);
    info!("Logfile verbosity level: {}", log_level);
    info!("Writing to log file: {}", log_file.display());
    debug!("Available interfaces: {:?}", interfaces);

    let configuration_directory = statics::PROJECT_DIRS.config_dir();
    debug!("Configuration path: {}", configuration_directory.display());

    // Force update of OUF database for MAC vendor lookups.
    if matches.is_present("update") {
        let ouf_db_path = db::sqlite3::get_ouf_path();
        db::sqlite3::download_ouf_database(ouf_db_path.to_str().unwrap());
    }

    // We require an interface so unwrap() is safe here.
    let interface = matches.value_of("interface").unwrap();
    let iface: String = interface.to_string();
    info!("Listening interface: {}", iface);

    // Create a thread for monitoring ARP packets.
    let (arp_tx, arp_rx) = mpsc::channel();
    thread::spawn(move || {
        net::arp::listen(iface, arp_tx);
    });
    
    let ouf_db_path = db::sqlite3::get_ouf_path();
    debug!("Loading ouf database from path: {:?}", &ouf_db_path);
    if !ouf_db_path.exists() {
        // Netgrasp will auto-install Wireshark's manuf file for vendor lookups.
        info!("Required ouf database (for vendor-lookups) not found: {:?}", &ouf_db_path);
        db::sqlite3::download_ouf_database(ouf_db_path.to_str().unwrap());
    }
    let path_to_ouf_db: &str = ouf_db_path.to_str().unwrap();

    let mut db_file;
    match matches.value_of("dbfile") {
        None => {
            let data_local_dir = statics::PROJECT_DIRS.data_local_dir();
            db_file = PathBuf::new();
            db_file.push(data_local_dir);
            db_file.push("netgrasp.db");
        }
        _ => {
            db_file = PathBuf::from(matches.value_of("dbfile").unwrap());
        }
    }
    fs::create_dir_all(&db_file.parent().unwrap()).expect("Failed to create database file.");
    let path_to_db: &str = db_file.to_str().unwrap();
    let netgrasp_db = db::sqlite3::NetgraspDb::new(path_to_db.to_string(), path_to_ouf_db.to_string());
    info!("Using database file: {}", path_to_db);
    netgrasp_db.create_database();

    loop {
        let received = arp_rx.recv().unwrap();
        netgrasp_db.log_arp_packet(received);
    }
}

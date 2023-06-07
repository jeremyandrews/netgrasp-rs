use clap::Parser;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mac_oui::Oui;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

mod arp;

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
struct Config {
    /// Interface(s) to listen on
    #[arg(short, long, value_delimiter = ',', value_name = "INT1,INT2,...")]
    interfaces: Vec<String>,
}

#[tokio::main]
async fn main() {
    // Start with toml configuration file.
    let config: Config = Figment::from(Toml::file("netgrasp.toml"))
        // Override with anything set in environment variables.
        .merge(Env::prefixed("NETGRASP_"))
        // Override with anything set via flags.
        .merge(Serialized::defaults(Config::parse()))
        .extract()
        .unwrap();

    // Interfaces must be configurex (typically in `netgrasp.toml` or NETGRASP_INTERFACES.)
    if config.interfaces.is_empty() {
        println!("\nAvailable interfaces: {}", list_interfaces().join(", "));
        println!("Usage: netgrasp --interfaces <INTERFACE1,INTERFACE2,...>\n");
        std::process::exit(1);
    }

    // Validate that only valid interfaces are being monitored.
    for interface in &config.interfaces {
        if !list_interfaces().contains(interface) {
            eprintln!("\nInvalid interface: {}", interface);
            println!("Available interfaces: {}", list_interfaces().join(", "));
            println!("Usage: netgrasp --interfaces <INTERFACE1,INTERFACE2,...>\n");
            std::process::exit(2);
        }
    }

    let oui_db = match Oui::default() {
        Ok(s) => s,
        Err(e) => {
            println!("Oui error: {}", e);
            std::process::exit(1)
        }
    };

    // Listen on configured interfaces.
    let (arp_tx, mut arp_rx) = mpsc::channel(2048);
    for interface in config.interfaces {
        let interface_arp_tx = arp_tx.clone();
        tokio::spawn(async move {
            arp::listen(interface.clone(), interface_arp_tx).await;
        });
    }

    loop {
        // Check for ARP packets at least 10 times a second.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        while let Ok(arp_packet) = arp_rx.try_recv() {
            // @TODO: Only do lookup if not already known.
            let source = map_mac_to_owner(
                &oui_db,
                arp_packet.arp_message.source_hardware_address.to_string(),
            );
            let target = map_mac_to_owner(
                &oui_db,
                arp_packet.arp_message.target_hardware_address.to_string(),
            );

            println!(
                "{}: {} ({}) to {} ({}) ",
                arp_packet.ifname,
                arp_packet.arp_message.source_protocol_address,
                source,
                arp_packet.arp_message.target_protocol_address,
                target,
            );
        }
    }
}

// List all interfaces.
fn list_interfaces() -> Vec<String> {
    let mut ifaces: Vec<String> = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap() {
        ifaces.push(iface.name);
    }
    ifaces.sort();
    ifaces.dedup();
    ifaces
}

// Map MAC to owner.
fn map_mac_to_owner(oui_db: &Oui, mac_address: String) -> String {
    let oui_lookup = oui_db.lookup_by_mac(&mac_address);
    match oui_lookup {
        Ok(r) => {
            if let Some(rec) = r {
                rec.company_name.to_string()
            } else {
                mac_address
            }
        }
        Err(e) => {
            println!("OUI lookup error: {}", e);
            mac_address
        }
    }
}

/*
use simplelog::*;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
mod db {
    pub mod models;
    pub mod oui;
    pub mod schema;
    pub mod sqlite3;
}
mod net {
    pub mod arp;
}
mod utils {
    pub mod format;
    pub mod math;
    pub mod statics;
    pub mod time;
}
mod notifications {
    pub mod templates;
}

// By default look for netscans happening over 30 minnutes
const DEFAULT_NETSCAN_RANGE: u64 = 30;
const DEFAULT_PROCESS_INACTIVE_IPS: u64 = 30;
const DEFAULT_PROCESS_NETSCANS: u64 = 30;
const DEFAULT_TMP_ACTIVE_DEVICES: u64 = 5;

const DEFAULT_MINIMUM_PRIORITY: &str = "140";

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
        .version(crate_version!())
        .author("Jeremy Andrews <jeremy@tag1consulting.com>")
        .about("A passive network observation tool")
        .arg(
            Arg::with_name("interface")
                .short("i")
                .long("interface")
                .value_name("INTERFACE")
                .help("Specify the network interface to listen on")
                .possible_values(&values)
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("logfile")
                .short("l")
                .long("logfile")
                .value_name("LOG FILE")
                .help("Path of logfile")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dbfile")
                .short("d")
                .long("dbfile")
                .value_name("DATABASE FILE")
                .help("Path of database file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("priority")
                .short("p")
                .long("priority")
                .value_name("PRIORITY")
                .help("Notify of events of this priority or more")
                .default_value(DEFAULT_MINIMUM_PRIORITY)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("update")
                .short("u")
                .long("update")
                .help("Update MAC addresses vendor db"),
        )
        .arg(
            Arg::with_name("g")
                .short("g")
                .multiple(true)
                .help("Sets the logged level of verbosity"),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the output level of verbosity"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .help("Include debug information in notifications"),
        )
        .get_matches();

    // Allow optionally controlling debug output level
    let debug_level;
    match matches.occurrences_of("v") {
        0 => debug_level = LevelFilter::Warn,
        1 => debug_level = LevelFilter::Info,
        2 => debug_level = LevelFilter::Debug,
        _ => debug_level = LevelFilter::Trace,
    }

    let log_level;
    match matches.occurrences_of("g") {
        0 => log_level = LevelFilter::Warn,
        1 => log_level = LevelFilter::Info,
        2 => log_level = LevelFilter::Debug,
        _ => log_level = LevelFilter::Trace,
    }

    let mut log_file;
    match matches.value_of("logfile") {
        None => {
            let data_local_dir = utils::statics::PROJECT_DIRS.data_local_dir();
            log_file = PathBuf::new();
            log_file.push(data_local_dir);
            log_file.push("netgrasp.log");
        }
        _ => {
            log_file = PathBuf::from(matches.value_of("logfile").unwrap());
        }
    }
    fs::create_dir_all(&log_file.parent().unwrap()).expect("Failed to create log file.");

    CombinedLogger::init(vec![
        TermLogger::new(debug_level, Config::default(), TerminalMode::Mixed).unwrap(),
        WriteLogger::new(
            log_level,
            Config::default(),
            File::create(&log_file).unwrap(),
        ),
    ])
    .unwrap();
    info!("Output verbosity level: {}", debug_level);
    info!("Logfile verbosity level: {}", log_level);
    info!("Writing to log file: {}", log_file.display());
    debug!("Available interfaces: {:?}", interfaces);

    let debug_in_notifications: bool;
    if matches.is_present("debug") {
        debug_in_notifications = true;
        info!("Debug enabled in notifications.");
    }
    else {
        debug_in_notifications = false;
    }


    let configuration_directory = utils::statics::PROJECT_DIRS.config_dir();
    debug!("Configuration path: {}", configuration_directory.display());

    let min_priority = value_t_or_exit!(matches.value_of("priority"), u8);
    info!(
        "Notifying of events with a priority of {} or more.",
        min_priority
    );

    // Force update of OUI database for MAC vendor lookups.
    if matches.is_present("update") {
        let oui_db_path = db::oui::get_path();
        db::oui::download_file(oui_db_path.to_str().unwrap());
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

    let oui_db_path = db::oui::get_path();
    debug!("Loading oui database from path: {:?}", &oui_db_path);
    if !oui_db_path.exists() {
        // Netgrasp will auto-install Wireshark's manuf file for vendor lookups.
        info!(
            "Required oui database (for vendor-lookups) not found: {:?}",
            &oui_db_path
        );
        db::oui::download_file(oui_db_path.to_str().unwrap());
    }
    let path_to_oui_db: &str = oui_db_path.to_str().unwrap();

    let mut db_file;
    match matches.value_of("dbfile") {
        None => {
            let data_local_dir = utils::statics::PROJECT_DIRS.data_local_dir();
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
    let netgrasp_db = db::sqlite3::NetgraspDb::new(
        path_to_db.to_string(),
        path_to_oui_db.to_string(),
        min_priority,
        debug_in_notifications,
    );
    info!("Using SQLite3 database file: {}", path_to_db);
    let response = netgrasp_db.migrate();
    match response {
        Err(e) => eprintln!("database migration error: {}", e),
        Ok(_) => (),
    }

    let mut last_processed_inactive_ips: u64 = 0;
    let mut last_processed_network_scans: u64 = 0;
    let mut netscan_range = DEFAULT_NETSCAN_RANGE;

    let mut last_tmp_display_active_devices: u64 = 0;

    loop {
        trace!("top of main loop");
        match arp_rx.recv() {
            Ok(r) => netgrasp_db.record_network_event(r),
            Err(e) => {
                error!("fatal error, exiting: [{}]", e);
                std::process::exit(1);
            }
        }

        let now = utils::time::timestamp_now();
        if (now - DEFAULT_TMP_ACTIVE_DEVICES) > last_tmp_display_active_devices {
            last_tmp_display_active_devices = now;
            // proof of concept: display current list of known active devices.
            let active_devices = netgrasp_db.get_active_devices();
            utils::format::display_active_devices(active_devices);
        }

        if (now - DEFAULT_PROCESS_INACTIVE_IPS) > last_processed_inactive_ips {
            last_processed_inactive_ips = now;
            netgrasp_db.process_inactive_ips();
        }

        if (now - DEFAULT_PROCESS_NETSCANS) > last_processed_network_scans {
            last_processed_network_scans = now;
            match netgrasp_db.detect_netscan(netscan_range) {
                true => {
                    // Once we detect a netscan, we shrink the range to only 1 minute so we
                    // don't keep re-detecting the same scan. We slowly increase the range by
                    // 1 minute each minute until we get back to the DEFAULT_NETSCAN_RANGE.
                    netscan_range = 1;
                    info!(
                        "netscan detected, decreasing netscan range to {}",
                        netscan_range
                    );
                }
                false => {
                    // This assumes process_network_scan_every is 60 seconds, otherwise this
                    // logic needs to be changed so the range increases correctly.
                    if netscan_range < DEFAULT_NETSCAN_RANGE {
                        netscan_range += 1;
                        info!("increasing netscan range to {}", netscan_range);
                    }
                }
            }
        }
    }
}
*/

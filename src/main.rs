use clap::Parser;
use dns_lookup::lookup_addr;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mac_oui::Oui;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use std::net::{IpAddr, Ipv4Addr};

mod arp;
mod db;

#[derive(Debug)]
pub(crate) struct NetgraspIp<'a> {
    interface: &'a str,
    address: &'a str,
    host: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct NetgraspActiveDevice {
    pub interface: String,
    pub ip_address: String,
    pub mac_address: String,
    pub host_name: String,
    pub vendor_name: String,
    pub vendor_full_name: String,
    pub custom_name: String,
    pub recently_seen_count: i64,
    pub recently_seen_first: i32,
    pub recently_seen_last: i32,
}

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
struct Config {
    /// Interface(s) to listen on
    #[arg(short, long, value_delimiter = ',', value_name = "INT1,INT2,...")]
    interfaces: Vec<String>,

    /// Path and name of database
    #[arg(short, long)]
    database: Option<String>,
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

    // Load the Oui database for MAC address lookups.
    // @TODO: support configurable path to load `from_csv_file`.
    // https://docs.rs/mac_oui/latest/mac_oui/struct.Oui.html#method.from_csv_file
    let oui_db = match Oui::default() {
        Ok(s) => s,
        Err(e) => {
            println!("Oui error: {}", e);
            std::process::exit(1)
        }
    };

    // @TODO: Allow configuration of PostgreSQL or MySQL database.
    let default_db_name = "netgrasp.db".to_string();
    let database_name = config.database.as_ref().unwrap_or(&default_db_name);
    let database_url = format!("sqlite://{}", database_name);

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
            let device = get_device_from_mac(
                &oui_db,
                &arp_packet.arp_message.source_hardware_address.to_string(),
            );
            let host = get_host_from_ip(&arp_packet.arp_message.source_protocol_address);

            let mac_id = db::record_mac(&database_url, &arp_packet.arp_message).await;
            let ip_id = db::record_ip(
                &database_url,
                &NetgraspIp {
                    interface: &arp_packet.ifname,
                    address: &arp_packet.arp_message.source_protocol_address.to_string(),
                    host: host.as_deref(),
                },
            )
            .await;

            if let (Some(m), Some(i)) = (mac_id, ip_id) {
                let _ = db::record_activity(
                    &database_url,
                    &arp_packet.ifname,
                    m,
                    arp_packet.arp_message.source_hardware_address.to_string(),
                    device,
                    i,
                    arp_packet.arp_message.source_protocol_address.to_string(),
                    host,
                )
                .await;
            }
        }

        println!("{:#?}", db::get_active_devices(&database_url).await);
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
fn get_device_from_mac(oui_db: &Oui, mac_address: &str) -> Option<String> {
    let oui_lookup = oui_db.lookup_by_mac(mac_address);
    match oui_lookup {
        Ok(r) => {
            if let Some(rec) = r {
                Some(rec.company_name.to_string())
            } else {
                None
            }
        }
        Err(e) => {
            println!("OUI lookup error: {}", e);
            None
        }
    }
}

// Map IPv4 address to hostname.
// @TODO: Also support IPv6.
fn get_host_from_ip(ip_address: &Ipv4Addr) -> Option<String> {
    match lookup_addr(&IpAddr::V4(*ip_address)) {
        Ok(a) => Some(a.to_string()),
        Err(_) => None,
    }
}

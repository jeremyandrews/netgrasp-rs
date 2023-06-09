use clap::Parser;
use dns_lookup::lookup_addr;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use libarp::arp::ArpMessage;
use mac_oui::Oui;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use std::net::{IpAddr, Ipv4Addr};

//use netgrasp_entity::activity_log;
//use netgrasp_entity::ip;
//use netgrasp_entity::mac;
use netgrasp_entity::{prelude::*, *};

mod arp;
mod db;


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
            // @TODO: Only do MAC lookup if not already known.
            let source_hardware = map_mac_to_owner(
                &oui_db,
                arp_packet.arp_message.source_hardware_address.to_string(),
            );
            let target_hardware = map_mac_to_owner(
                &oui_db,
                arp_packet.arp_message.target_hardware_address.to_string(),
            );

            // @TODO: Only do DNS lookup if not already known.
            let source_address =
                map_ip_to_hostname(&arp_packet.arp_message.source_protocol_address);
            let target_address =
                map_ip_to_hostname(&arp_packet.arp_message.target_protocol_address);

            println!(
                "{}: {} ({}) to {} ({}) ",
                arp_packet.ifname, source_address, source_hardware, target_address, target_hardware,
            );

            let mac_id = record_mac(&arp_packet.arp_message, &database_url).await;
            println!("mac_id [{}]: {}", mac_id.unwrap(), source_hardware)
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

// Map IPv4 address to hostname.
// @TODO: Also support IPv6.
fn map_ip_to_hostname(ip_address: &Ipv4Addr) -> String {
    match lookup_addr(&IpAddr::V4(*ip_address)) {
        Ok(a) => a.to_string(),
        Err(_) => {
            // No hostname, return IP address.
            ip_address.to_string()
        }
    }
}

async fn record_mac(arp_message: &ArpMessage, database_url: &str) -> Option<i32> {
    let mac = {
        let db = db::connection(database_url).await;
        match Mac::find()
            .filter(mac::Column::HardwareAddress.like(&arp_message.source_hardware_address.to_string()))
            .one(db)
            .await
        {
            Ok(m) => m,
            Err(_) => return None,
        }
    };
    if let Some(m) = mac {
        Some(m.mac_id)
    } else {
        let new_mac = mac::ActiveModel {
            // @TODO: On SQLite this is apparently a string?
            //created: Set(chrono::Utc::now().naive_utc().to_owned()),
            created: Set(chrono::Utc::now().naive_utc().to_string()),
            hardware_address: Set(arp_message.source_hardware_address.to_string()),
            protocol_address: Set(arp_message.source_protocol_address.to_string()),
            ..Default::default()
        };
        let new_mac_id = {
            let db = db::connection(database_url).await;
            Mac::insert(new_mac)
                .exec(db)
                .await
                .expect("failed to write mac to database")
        };
        Some(new_mac_id.last_insert_id)
    }
}

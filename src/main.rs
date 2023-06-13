use clap::Parser;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mac_oui::Oui;
use netgrasp_entity::{prelude::*, *};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::sync::mpsc;

mod arp;
mod audit;
mod db;
mod utils;

// Mac addresses are considered active for 2.5 hours after being seen.
// @TODO: Add a per-device adjustment based on patterns.
pub(crate) static MINUTES_ACTIVE_FOR: i64 = 150;

#[derive(Debug)]
pub(crate) struct NetgraspIp<'a> {
    interface: &'a str,
    address: &'a str,
    host: Option<&'a str>,
}

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
pub struct Config {
    /// Interface(s) to listen on
    #[arg(short, long, value_delimiter = ',', value_name = "INT1,INT2,...")]
    interfaces: Vec<String>,

    /// Path and name of database
    #[arg(short, long)]
    database: Option<String>,

    /// Identify mac with custom name
    #[arg(long)]
    identify: bool,

    /// Optional Slack notification channel
    #[arg(short, long)]
    slack_channel: Option<String>,

    /// Optional Slack webhook
    #[arg(short, long)]
    slack_webhook: Option<String>,
}

#[tokio::main]
async fn main() {
    // Start with toml configuration file.
    // @TODO @fixme it's not working as intended
    let config: Config = Figment::from(Toml::file("netgrasp.toml"))
        // Override with anything set in environment variables.
        .adjoin(Env::prefixed("NETGRASP_"))
        // Override with anything set via flags.
        .adjoin(Serialized::defaults(Config::parse()))
        .extract()
        .unwrap();

    println!("Config: {:#?}", config);

    // @TODO: Allow configuration of PostgreSQL or MySQL database.
    let default_db_name = "netgrasp.db".to_string();
    let database_name = config.database.as_ref().unwrap_or(&default_db_name);
    let database_url = format!("sqlite://{}", database_name);

    if config.identify {
        println!("Identify MAC addresses...");

        let macs = {
            let db = db::connection(&database_url).await;
            // @TODO: Optimize this with a single join query?
            // Start with all known Mac IDs. Get all known Mac IDs.
            match recent_activity::Entity::find()
                // Consider each recently seen Mac a single time.
                .group_by(recent_activity::Column::MacId)
                // Start with most recently seen first.
                .order_by_desc(recent_activity::Column::Timestamp)
                .all(db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("list all mac addresses query error: {}", e);
                    Vec::new()
                }
            }
        };

        for mac in macs {
            let identified_mac = {
                let db = db::connection(&database_url).await;
                match custom::Entity::find()
                    .filter(custom::Column::MacId.eq(mac.mac_id))
                    .one(db)
                    .await
                {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("find unidentified mac addresses query error: {}", e);
                        None
                    }
                }
            };
            if identified_mac.is_none() {
                if let Some(custom) = mac.custom {
                    println!("Identified mac address:");
                    println!(" - Custom: {}", custom);
                } else {
                    println!("Unidentified Mac address:");
                }
                println!(" - Interface: {}", mac.interface);
                if let Some(host) = mac.host {
                    println!(" - Host: {}", host);
                }
                println!(" - Ip: {}", mac.ip);
                if let Some(vendor) = mac.vendor {
                    println!(" - Vendor: {}", vendor);
                }
                println!(" - Mac: {}", mac.mac);
                println!(" - Last seen: {}", utils::time_ago(mac.timestamp, false));

                let mut buffer = String::new();
                let stdin = io::stdin();
                let _ = stdin.read_line(&mut buffer);

                if !buffer.trim().is_empty() {
                    let new_custom = custom::ActiveModel {
                        created: Set(chrono::Utc::now().naive_utc().to_string()),
                        updated: Set(chrono::Utc::now().naive_utc().to_string()),
                        mac_id: Set(mac.mac_id),
                        ip_id: Set(mac.ip_id),
                        name: Set(buffer.trim().to_string()),
                        ..Default::default()
                    };
                    let _ = {
                        let db = db::connection(&database_url).await;
                        Custom::insert(new_custom)
                            .exec(db)
                            .await
                            .expect("failed to write custom to database")
                    };
                    println!("Set custom name to: '{}'\n", buffer.trim());
                }
            }
        }

        std::process::exit(0);
    }

    // Interfaces must be configurex (typically in `netgrasp.toml` or NETGRASP_INTERFACES.)
    if config.interfaces.is_empty() {
        println!(
            "\nAvailable interfaces: {}",
            utils::list_interfaces().join(", ")
        );
        println!("Usage: netgrasp --interfaces <INTERFACE1,INTERFACE2,...>\n");
        std::process::exit(1);
    }

    // Validate that only valid interfaces are being monitored.
    for interface in &config.interfaces {
        if !utils::list_interfaces().contains(interface) {
            eprintln!("\nInvalid interface: {}", interface);
            println!(
                "Available interfaces: {}",
                utils::list_interfaces().join(", ")
            );
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

    // Listen on configured interfaces.
    let (arp_tx, mut arp_rx) = mpsc::channel(2048);
    for interface in config.interfaces.clone() {
        let interface_arp_tx = arp_tx.clone();
        tokio::spawn(async move {
            arp::listen_loop(interface.clone(), interface_arp_tx).await;
        });
    }

    // Spawn a thread to perform tasks like cleaning up old messages, sending notifications,
    // and detecting patterns.
    let audit_database_url = database_url.clone();
    tokio::spawn(async move {
        audit::audit_loop(audit_database_url, &config).await;
    });

    // @TODO: display every X seconds
    let mut last_displayed = 0;
    loop {
        // Check for ARP packets at least 10 times a second.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        while let Ok(arp_packet) = arp_rx.try_recv() {
            let device = utils::get_device_from_mac(
                &oui_db,
                &arp_packet.arp_message.source_hardware_address.to_string(),
            );
            let host = utils::get_host_from_ip(&arp_packet.arp_message.source_protocol_address);

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

        // Output recently seen devices every 10 seconds.
        // @TODO: make this configurable.
        if utils::timestamp_now() - last_displayed > 10 {
            utils::display_active_devices(db::get_active_devices(&database_url).await);
            last_displayed = utils::timestamp_now();
        }
    }
}

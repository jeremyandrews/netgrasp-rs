use chrono::naive::NaiveDateTime;
use clap::Parser;
use dns_lookup::lookup_addr;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use mac_oui::Oui;
use netgrasp_entity::recent_activity;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use chrono::Days;

use sea_orm::ColumnTrait;
use sea_orm::EntityTrait;
use sea_orm::QueryFilter;

use std::net::{IpAddr, Ipv4Addr};

mod arp;
mod db;

use crate::db::ActiveDevice;

#[derive(Debug)]
pub(crate) struct NetgraspIp<'a> {
    interface: &'a str,
    address: &'a str,
    host: Option<&'a str>,
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

    // Spawn a thread to perform tasks like cleaning up old messages, sending notifications,
    // and detecting patterns.
    let audit_database_url = database_url.clone();
    tokio::spawn(async move {
        audit(audit_database_url).await;
    });

    // @TODO: display every X seconds
    let mut last_displayed = 0;
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

        if last_displayed > 100 {
            display_active_devices(db::get_active_devices(&database_url).await);
            last_displayed = 0;
        } else {
            last_displayed += 1;
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

// Display a list of all active devices
pub fn display_active_devices(active_devices: Vec<ActiveDevice>) {
    println!("Active devices:");
    // {:>##} gives the column a fixed width of ## characters, aligned right
    println!("{:>34} {:>16} {:>22}", "Name", "IP", "Last Seen");
    for device in active_devices.iter() {
        let name = device_name(DeviceName {
            host: device.host.clone(),
            vendor: device.vendor.clone(),
            mac: device.mac.to_string(),
            ip: device.ip.to_string(),
        });
        println!(
            "{:>34} {:>16} {:>22}",
            truncate_string(name, 33),
            truncate_string(device.ip.to_string(), 16),
            time_ago(device.recently_seen_last.to_string(), false)
        );
    }
}

pub struct DeviceName {
    //pub custom_name: String,
    pub host: Option<String>,
    pub vendor: Option<String>,
    pub mac: String,
    pub ip: String,
}

pub fn device_name(device: DeviceName) -> String {
    //if device.custom_name != "" {
    //    device.custom_name.to_string()
    //} else if device.host_name != "" && device.host_name != device.ip_address {
    if let Some(host) = device.host {
        host
    } else if let Some(vendor) = device.vendor {
        vendor
    } else {
        device.mac
    }
}

pub(crate) fn truncate_string(mut string_to_truncate: String, max_length: u64) -> String {
    if string_to_truncate.len() as u64 > max_length {
        let truncated_length = max_length - 3;
        string_to_truncate.truncate(truncated_length as usize);
        string_to_truncate = string_to_truncate + "...";
    }
    string_to_truncate
}

pub(crate) fn time_ago(timestamp_string: String, precision: bool) -> String {
    // @TODO: error handling.
    let timestamp = NaiveDateTime::parse_from_str(&timestamp_string, "%Y-%m-%d %H:%M:%S.%f")
        .unwrap()
        .timestamp() as u64;

    let mut seconds: u64 = time_elapsed(timestamp);
    let days: u64 = seconds / 86400;
    let remainder_string;

    match days {
        0 => match seconds {
            0..=9 => "just now".to_string(),
            10..=59 => seconds.to_string() + " seconds ago",
            60..=119 => "a minute ago".to_string(),
            120..=3599 => {
                let time_string = (seconds / 60).to_string()
                    + " minutes "
                    + match precision {
                        true => {
                            let remainder = seconds % 60;
                            match remainder {
                                0 => "ago",
                                1 => "1 second ago",
                                _ => {
                                    remainder_string = format!("{} seconds ago", remainder);
                                    remainder_string.as_str()
                                }
                            }
                        }
                        false => "ago",
                    };
                time_string
            }
            3600..=7199 => "an hour ago".to_string(),
            _ => {
                let time_string = format!("{} hours ", seconds / 3600)
                    + match precision {
                        true => {
                            let remainder: u64 = (seconds % 3600) / 60;
                            match remainder {
                                0 => "ago",
                                1 => "1 minute ago",
                                _ => {
                                    remainder_string = format!("{} minutes ago", remainder);
                                    remainder_string.as_str()
                                }
                            }
                        }
                        false => "ago",
                    };
                time_string
            }
        },
        1 => {
            let time_string = "1 day ".to_string()
                + match precision {
                    true => {
                        seconds = seconds - 86400;
                        match seconds {
                            0..=119 => "ago",
                            120..=3599 => {
                                remainder_string = format!("{} minutes ago", seconds / 60);
                                remainder_string.as_str()
                            }
                            3600..=7199 => "1 hour ago",
                            _ => {
                                remainder_string = format!("{} hours ago", seconds / 3600);
                                remainder_string.as_str()
                            }
                        }
                    }
                    false => "ago",
                };
            time_string
        }
        2..=6 => {
            let time_string = format!("{} days ", days)
                + match precision {
                    true => {
                        seconds = seconds - 86400 * days;
                        match seconds {
                            0..=7199 => "ago",
                            _ => {
                                remainder_string = format!("{} hours ago", seconds / 3600);
                                remainder_string.as_str()
                            }
                        }
                    }
                    false => "ago",
                };
            time_string
        }
        7 => {
            let time_string = format!("1 week ")
                + match precision {
                    true => {
                        let remainder: u64 = (days % 7) / 60;
                        match remainder {
                            0 => "ago",
                            1 => "1 day ago",
                            _ => {
                                remainder_string = format!("{} days ago", remainder);
                                remainder_string.as_str()
                            }
                        }
                    }
                    false => "ago",
                };
            time_string
        }
        8..=30 => {
            let time_string = format!("{} weeks ", (days / 7) as u64)
                + match precision {
                    true => {
                        let remainder: u64 = (days % 7) / 60;
                        match remainder {
                            0 => "ago",
                            1 => "1 day ago",
                            _ => {
                                remainder_string = format!("{} days ago", remainder);
                                remainder_string.as_str()
                            }
                        }
                    }
                    false => "ago",
                };
            time_string
        }
        31..=364 => {
            let time_string = format!("{} months ", (days / 30) as u64)
                + match precision {
                    true => {
                        let day_remainder: u64 = days % 30;
                        match day_remainder {
                            0 => "ago",
                            1 => "1 day ago",
                            2..=6 => {
                                remainder_string = format!("{} days ago", day_remainder);
                                remainder_string.as_str()
                            }
                            _ => {
                                let week_remainder: u64 = day_remainder / 7;
                                match week_remainder {
                                    1 => "1 week ago",
                                    _ => {
                                        remainder_string = format!("{} weeks ago", week_remainder);
                                        remainder_string.as_str()
                                    }
                                }
                            }
                        }
                    }
                    false => "ago",
                };
            time_string
        }
        _ => {
            let time_string = format!("{} years ", days / 365)
                + match precision {
                    true => {
                        let day_remainder = days % 365;
                        match day_remainder {
                            0 => "ago",
                            1 => "1 day ago",
                            2..=6 => {
                                remainder_string = format!("{} days ago", day_remainder);
                                remainder_string.as_str()
                            }
                            _ => {
                                let week_remainder = days % 7;
                                match week_remainder {
                                    0 => "ago",
                                    1 => "1 week ago",
                                    2..=4 => {
                                        remainder_string = format!("{} weeks ago", week_remainder);
                                        remainder_string.as_str()
                                    }
                                    _ => {
                                        let month_remainder = days % 12;
                                        match month_remainder {
                                            0 => "ago",
                                            1 => "1 month ago",
                                            _ => {
                                                remainder_string =
                                                    format!("{} months ago", month_remainder);
                                                remainder_string.as_str()
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    false => "ago",
                };
            time_string
        }
    }
}

pub(crate) fn timestamp_now() -> u64 {
    let start = SystemTime::now();
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub(crate) fn time_elapsed(timestamp: u64) -> u64 {
    timestamp_now() - timestamp
}

pub async fn audit(database_url: String) {
    let mut every_second = 0;
    loop {
        // Every second...
        if timestamp_now() - every_second > 1 {
            let db = db::connection(&database_url).await;
            every_second = timestamp_now();

            let yesterday = chrono::Utc::now()
                .naive_utc()
                .checked_sub_days(Days::new(1))
                .unwrap()
                .to_string();

            let _res = match recent_activity::Entity::delete_many()
                .filter(recent_activity::Column::Timestamp.gt(yesterday))
                .exec(db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("fatal database error: {}", e);
                    std::process::exit(1);
                }
            };
            //println!("deleted {:?} rows from recent_activity table.", res);
        }

        // Loop 4 times per second.
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
}

// Helper functions.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::naive::NaiveDateTime;
use dns_lookup::lookup_addr;
use mac_oui::Oui;

use crate::recent_activity::Model;
use crate::{db, Config};

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

// Display a list of all active devices
pub fn display_active_devices(active_devices: Vec<db::ActiveDevice>, config: &Config) {
    println!("Active devices:");
    // {:>##} gives the column a fixed width of ## characters, aligned right
    println!("{:>34} {:>16} {:>22}", "Name", "IP", "Last Seen");
    for device in active_devices.iter() {
        let mut display = true;
        if let Some(custom) = device.custom.as_ref() {
            for filter in &config.custom_hide_filters {
                if custom
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
                {
                    display = false;
                    break;
                }
            }
        }
        if display {
            let name = device_name(DeviceName {
                custom: device.custom.clone(),
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
}

pub struct DeviceName {
    pub custom: Option<String>,
    pub host: Option<String>,
    pub vendor: Option<String>,
    pub mac: String,
    pub ip: String,
}

pub fn device_name(device: DeviceName) -> String {
    if let Some(custom) = device.custom {
        custom
    } else if let Some(host) = device.host {
        host
    } else if let Some(vendor) = device.vendor {
        vendor
    } else {
        device.mac
    }
}

// List all interfaces.
pub(crate) fn list_interfaces() -> Vec<String> {
    let mut ifaces: Vec<String> = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap() {
        ifaces.push(iface.name);
    }
    ifaces.sort();
    ifaces.dedup();
    ifaces
}

// Map MAC to owner.
pub(crate) fn get_device_from_mac(oui_db: &Oui, mac_address: &str) -> Option<String> {
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
pub(crate) fn get_host_from_ip(ip_address: &Ipv4Addr) -> Option<String> {
    match lookup_addr(&IpAddr::V4(*ip_address)) {
        Ok(a) => Some(a.to_string()),
        Err(_) => None,
    }
}

pub(crate) async fn display_mac_details(database_url: &str, mac: &Model) {
    let stats = db::get_mac_stats(database_url, &mac.mac).await;
    if let Some(custom) = mac.custom.as_ref() {
        println!("Identified mac address:");
        println!(" - Custom: {}", custom);
    } else {
        println!("Unidentified Mac address:");
    }
    println!(" - Interface: {}", mac.interface);
    if let Some(host) = mac.host.as_ref() {
        println!(" - Host: {}", host);
    }
    println!(" - Ip: {}", mac.ip);
    if let Some(vendor) = mac.vendor.as_ref() {
        println!(" - Vendor: {}", vendor);
    }
    println!(" - Mac: {}", mac.mac);
    if let Some(recent) = stats {
        if let Some(timestamp) = recent.seen_recently {
            println!(" - Last seen: {}", time_ago(timestamp, false));
        }
        println!(" - Times seen recently: {}", recent.seen_count);
        println!(" - First seen: {}", time_ago(recent.seen_first, false));
    }
}

use crate::db::sqlite3::{NetgraspActiveDevice};

// Display a list of all active devices
pub fn display_active_devices(active_devices: Vec<NetgraspActiveDevice>) {
    println!("Active devices:");
    // {:>##} gives the column a fixed width of ## characters, aligned right
    println!("{:>34} {:>16} {:>22}", "Name", "IP", "Last Seen");
    for device in active_devices.iter() {
        let name: String;
        if device.custom_name != "" {
            name = device.custom_name.to_string();
        }
        else if device.host_name != "" && device.host_name != device.ip_address {
            name = device.host_name.to_string();
        }
        else {
            name = device.vendor_full_name.to_string();
        }
        println!("{:>34} {:>16} {:>22}", truncate_string(name, 33), truncate_string(device.ip_address.to_string(), 16), time_ago(device.recently_seen_last as u64, false));
    }
}

pub fn truncate_string(mut string_to_truncate: String, max_length: u64) -> String {
    if string_to_truncate.len() as u64 > max_length {
        let truncated_length = max_length - 3;
        string_to_truncate.truncate(truncated_length as usize);
        string_to_truncate = string_to_truncate + "...";
    }
    string_to_truncate
}

pub fn time_ago(timestamp: u64, precision: bool)-> String {
    let mut seconds: u64 = crate::utils::time::elapsed(timestamp);
    let days: u64 = seconds / 86400;
    let remainder_string;

    match days {
        0 => {
            match seconds {
                0..=9 => "just now".to_string(),
                10..=59 => seconds.to_string() + " seconds ago",
                60..=119 => "a minute ago".to_string(),
                120..=3599 => {
                    let time_string = (seconds / 60).to_string() + " minutes " + match precision {
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
                3600..=7199  => {
                    "an hour ago".to_string()
                }
                _ => {
                    let time_string = format!("{} hours ", seconds / 3600) + match precision {
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
            }
        },
        1 => {
            let time_string = "1 day ".to_string() + match precision {
                true => {
                    seconds = seconds - 86400;
                    match seconds {
                        0..=119 => "ago",
                        120..=3599 => {
                            remainder_string = format!("{} minutes ago", seconds / 60);
                            remainder_string.as_str()
                        },
                        3600..=7199 => "1 hour ago",
                        _ => {
                            remainder_string = format!("{} hours ago", seconds / 3600);
                            remainder_string.as_str()
                        },
                    }
                },
                false => "ago",
            };
            time_string
        },
        2..=6 => {
            let time_string = format!("{} days ", days) + match precision {
                true => {
                    seconds = seconds - 86400 * days;
                    match seconds {
                        0..=7199 => "ago",
                        _ => {
                            remainder_string = format!("{} hours ago", seconds / 3600);
                            remainder_string.as_str()
                        },
                    }
                },
                false => "ago",
            };
            time_string
        },
        7..=30 => {
            let time_string = format!("{} weeks ", (days / 7) as u64) + match precision {
                true => {
                    let remainder: u64 = (days % 7) / 60;
                    match remainder {
                        0 => "ago",
                        1 => "1 day ago",
                        _ => {
                            remainder_string = format!("{} days ago", remainder);
                            remainder_string.as_str()
                        },
                    }
                },
                false => "ago",
            };
            time_string
        },
        31..=364 => {
            let time_string = format!("{} months ", (days / 30) as u64) + match precision {
                true => {
                    let day_remainder: u64 = days % 30;
                    match day_remainder {
                        0 => "ago",
                        1 => "1 day ago",
                        2..=6 => {
                            remainder_string = format!("{} days ago", day_remainder);
                            remainder_string.as_str()
                        },
                        _ => {
                            let week_remainder: u64 = day_remainder / 7;
                            match week_remainder {
                                1 => "1 week ago",
                                _ => {
                                    remainder_string = format!("{} weeks ago", week_remainder);
                                    remainder_string.as_str()
                                },
                            }
                        }
                    }
                },
                false => "ago",
            };
            time_string
        },
        _ => {
            let time_string = format!("{} years ", days / 365) + match precision {
                true => {
                    let day_remainder = days % 365;
                    match day_remainder {
                        0 => "ago",
                        1 => "1 day ago",
                        2..=6 => {
                            remainder_string = format!("{} days ago", day_remainder);
                            remainder_string.as_str()
                        },
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
                                            remainder_string = format!("{} months ago", month_remainder);
                                            remainder_string.as_str()
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
                false => "ago",
            };
            time_string
        }
    }
}
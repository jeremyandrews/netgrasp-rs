use crate::db::sqlite3::{NetgraspActiveDevice};

pub fn display_active_devices(active_devices: Vec<NetgraspActiveDevice>) {
    println!("Active devices:");
    println!("{:>34} {:>16} {:>22}", "Name", "IP", "Last Seen");
    for device in active_devices.iter() {
        let name: &str;
        if !device.host_name.is_empty() && device.host_name != device.ip_address {
            name = &device.host_name;
        }
        else {
            name = &device.vendor_full_name;
        }
        println!("{:>34} {:>16} {:>22}", name, &device.ip_address, time_ago(device.recently_seen_last as u64));
    }
}

pub fn time_ago(timestamp: u64)-> String {
    let seconds = crate::utils::time::elapsed(timestamp);
    // Activity in the past 10 seconds is shown as "just now"
    if seconds < 10 {
        return "just now".to_string()
    }

    // Next check if activity in past minute, and display as seconds.
    if seconds < 60 {
        return seconds.to_string() + " seconds ago"
    }

    // Next check if activity in past hour, and display in minutes.
    let minutes = seconds / 60;
    if minutes == 1 {
        return minutes.to_string() + " minute ago"
    }
    else if minutes < 60 {
        return minutes.to_string() + " minutes ago"
    }

    // Next check if activity in past day, and display in hours.
    let hours = minutes / 60;
    if hours == 1 {
        return hours.to_string() + " hour ago"
    }
    else if hours < 24 {
        return hours.to_string() + " hours ago"
    }

    // Next check if activity in past week, and display in days.
    let days = hours / 24;
    if days == 1 {
        return days.to_string() + " day ago"
    }
    else if days < 7 {
        return days.to_string() + " days ago"
    }

    // If we get here, display time in weeks.
    let weeks = days / 7;
    if weeks == 1 {
        return weeks.to_string() + " week ago"
    }
    else if weeks < 5 {
        return weeks.to_string() + " weeks ago"
    }

    // If we get here, display time in months.
    let months = days / 30;
    if months == 1 {
        return months.to_string() + " month ago"
    }
    else if months < 12 {
        return months.to_string() + " months ago"
    }

    // If we get here, display time in years.
    let years = days / 365;
    if years == 1 {
        years.to_string() + " year ago"
    }
    else {
        years.to_string() + " years ago"
    }
}
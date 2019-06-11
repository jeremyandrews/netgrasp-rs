use crate::db::sqlite3::{NetgraspActiveDevice};

pub fn display_active_devices(active_devices: Vec<NetgraspActiveDevice>) {
    println!("Active devices:");
    println!("{:>16} {:>34} {:>22}", "IP", "Name", "Last Seen");
    for device in active_devices.iter() {
        println!("{:>16} {:>34} {:>22}", &device.ip_address, &device.vendor_full_name, &device.recently_seen_last);
    }
}
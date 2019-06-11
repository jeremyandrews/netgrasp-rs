use smoltcp::wire::{ArpOperation};
use sqlite::Value;
use dns_lookup::{lookup_addr};
use eui48::MacAddress;
use oui::OuiDatabase;
use crate::utils::time;

pub struct NetgraspDb {
    sql: sqlite::Connection,
    oui: OuiDatabase,
}

#[derive(Debug)]
pub struct NetgraspEvent {
    timestamp: i64,
    interface: String,
    mac_id: i64,
    ip_id: i64,
    host_name: String,
    vendor_id: i64,
    vendor_name: String,
    vendor_full_name: String,
}

#[derive(Debug)]
pub struct NetgraspActiveDevice {
    pub interface: String,
    pub ip_address: String,
    pub mac_address: String,
    pub host_name: String,
    pub vendor_name: String,
    pub vendor_full_name: String,
    pub recently_seen_count: i64,
    pub recently_seen_first: i64,
    pub recently_seen_last: i64,
}

const EVENT_MAC_SEEN: &str = "mac seen";
const EVENT_MAC_SEEN_FIRST: &str = "mac first seen";
const EVENT_IP_REQUEST_FIRST: &str = "ip first request";
//const EVENT_IP_REQUEST_FIRST_RECENT: &str = "ip first recent request";
const EVENT_IP_REQUEST: &str = "ip request";
const EVENT_IP_SEEN: &str = "ip seen";
const EVENT_IP_SEEN_FIRST: &str = "ip first seen";
const EVENT_VENDOR_SEEN: &str = "vendor seen";
const EVENT_VENDOR_SEEN_FIRST: &str = "vendor first seen";
// EVENT_SEEN_DEVICE, EVENT_FIRST_SEEN_DEVICE, EVENT_FIRST_SEEN_DEVICE_RECENTLY, 
// EVENT_STALE, EVENT_REQUEST_STALE, EVENT_CHANGED_IP, EVENT_DUPLICATE_IP, EVENT_DUPLICATE_MAC, EVENT_SCAN, EVENT_IP_NOT_ON_NETWORK, EVENT_SRC_MAC_BROADCAST, EVENT_REQUESTED_SELF = ALERT_TYPES

impl NetgraspEvent {
    pub fn new(interface: String) -> Self {
        NetgraspEvent {
            timestamp: time::timestamp_now() as i64,
            interface: interface,
            mac_id: 0,
            ip_id: 0,
            host_name: "".to_string(),
            vendor_id: 0,
            vendor_name: "".to_string(),
            vendor_full_name: "".to_string(),
        }
    }
}

impl NetgraspDb {
    pub fn new(sql_database_path: String, oui_database_path: String) -> Self {
        NetgraspDb {
            sql: sqlite::open(sql_database_path).unwrap(),
            oui: OuiDatabase::new_from_file(oui_database_path.as_str()).unwrap(),
        }
    }

    // Returns a vector of all currently known active devices.
    pub fn get_active_devices(&self) -> Vec<NetgraspActiveDevice> {
        let mut active_devices = Vec::new();

        // @TODO: filter down to only recently seen
        let query = "SELECT interface, src_ip, src_mac, host_name, vendor_name, vendor_full_name, count(src_ip) AS source_ip_count, MIN(updated), MAX(updated) AS last_seen FROM arp WHERE src_ip != '0.0.0.0' GROUP BY src_ip ORDER BY last_seen DESC, source_ip_count DESC;";
        trace!("{}", &query);
        let mut cursor = self.sql
            .prepare(query)
            .unwrap()
            .cursor();

        //interface, src_mac_id, src_ip_id, tgt_ip_id, host_name, vendor_name, vendor_full_name src_mac, src_ip, tgt_mac, tgt_ip, operation, matched, created, updated) VALUES('{}', {}, {}, {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, {});",
        while let Some(row) = cursor.next().unwrap() {
            active_devices.push(NetgraspActiveDevice {
                interface: row[0].as_string().unwrap().to_string(),
                ip_address: row[1].as_string().unwrap().to_string(),
                mac_address: row[2].as_string().unwrap().to_string(),
                host_name: row[3].as_string().unwrap().to_string(),
                vendor_name: row[4].as_string().unwrap().to_string(),
                vendor_full_name: row[5].as_string().unwrap().to_string(),
                recently_seen_count: row[6].as_integer().unwrap(),
                recently_seen_first: row[7].as_integer().unwrap(),
                recently_seen_last: row[8].as_integer().unwrap(),
            });
        }
        active_devices
    }

    // Record each ARP packet we see.
    pub fn log_arp_packet(&self, arp_packet: crate::net::arp::NetgraspArpPacket) {
        trace!("log_arp_packet: {:?}", arp_packet);

        let operation: i64;
        // Object used to create events for the source side of the ARP message.
        let mut netgrasp_event_src = NetgraspEvent::new(arp_packet.interface.clone());
        // Object used to create events for the target side of the ARP message.
        let mut netgrasp_event_tgt = NetgraspEvent::new(arp_packet.interface.clone());

        match arp_packet.operation {
            ArpOperation::Request => {
                trace!("ARP request");
                // A MAC broadcast isn't a real MAC address, so don't store it.
                if arp_packet.src_is_broadcast {
                    debug!("ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
                }
                // Log all non-broadcast mac addresses.
                else {
                    netgrasp_event_src = self.load_mac_id(netgrasp_event_src, arp_packet.src_mac.to_string(), arp_packet.src_is_self as i64);
                }

                if arp_packet.src_ip != arp_packet.tgt_ip && arp_packet.src_mac != arp_packet.tgt_mac {
                    // A MAC broadcast isn't a real MAC address, so don't store it.
                    if arp_packet.tgt_is_broadcast {
                        debug!("ignoring arp broadcast target of {} [{}]", arp_packet.tgt_ip, arp_packet.tgt_mac)
                    }
                    // Log all non-broadcast IP addresses.
                    else {
                        // This is an ARP Request, we see an IP address without a MAC address.
                        netgrasp_event_tgt = self.load_ip_id(netgrasp_event_tgt, arp_packet.tgt_ip.to_string());
                    }
                }
                operation = 0;
            }
            ArpOperation::Reply => {
                trace!("ARP reply");
                // A MAC broadcast isn't a real MAC address, so don't store it.
                if arp_packet.src_is_broadcast {
                    debug!("ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
                }
                // Log all non-broadcast mac addresses.
                else {
                    netgrasp_event_src = self.load_mac_id(netgrasp_event_src, arp_packet.src_mac.to_string(), arp_packet.src_is_self as i64);
                }
                operation = 1;
            }
            _ => {
                info!("invalid ARP packet: {:?}", arp_packet);
                operation = -1;
            }
        }

        // We have a valid MAC address to associate with the IP address.
        if netgrasp_event_src.mac_id != 0 {
            debug!("source mac_id: {}", netgrasp_event_src.mac_id);
            // We don't record the broadcast of 0.0.0.0.
            if arp_packet.src_ip.to_string() == "0.0.0.0" {
                debug!("ignoring arp ip source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
            }
            // Record all other addresses.
            else {
                netgrasp_event_src = self.load_ip_id(netgrasp_event_src, arp_packet.src_ip.to_string());
                debug!("source ip_id: {}", netgrasp_event_src.ip_id);
            }
        }

        // We recorded the target IP in our database.
        if netgrasp_event_tgt.ip_id != 0 {
            debug!("target ip_id: {}", netgrasp_event_tgt.ip_id);
        }

        // @TODO update matched
        let matched = 0;
        trace!("INSERT INTO arp (interface, src_mac_id, src_ip_id, tgt_ip_id, host_name, vendor_name, vendor_full_name src_mac, src_ip, tgt_mac, tgt_ip, operation, matched, created, updated) VALUES('{}', {}, {}, {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, {});",
            &arp_packet.interface, netgrasp_event_src.mac_id, netgrasp_event_src.ip_id, netgrasp_event_tgt.ip_id, &netgrasp_event_src.host_name, &netgrasp_event_src.vendor_name, &netgrasp_event_src.vendor_full_name, arp_packet.src_mac.to_string(), arp_packet.src_ip.to_string(), arp_packet.tgt_mac.to_string(), arp_packet.tgt_ip.to_string(), operation, matched, netgrasp_event_src.timestamp, netgrasp_event_src.timestamp);
        let mut statement = self.sql.prepare("INSERT INTO arp
            (interface, src_mac_id, src_ip_id, tgt_ip_id, host_name, vendor_name, vendor_full_name, src_mac, src_ip, tgt_mac, tgt_ip, operation, matched, created, updated)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").unwrap();
        let bound_interface: &str = &arp_packet.interface;
        statement.bind(1, bound_interface).unwrap();
        statement.bind(2, netgrasp_event_src.mac_id).unwrap();
        statement.bind(3, netgrasp_event_src.ip_id).unwrap();
        statement.bind(4, netgrasp_event_tgt.ip_id).unwrap();
        let bound_host_name: &str = &netgrasp_event_src.host_name.to_string();
        statement.bind(5, bound_host_name).unwrap();
        let bound_vendor_name: &str = &netgrasp_event_src.vendor_name.to_string();
        statement.bind(6, bound_vendor_name).unwrap();
        let bound_vendor_full_name: &str = &netgrasp_event_src.vendor_full_name.to_string();
        statement.bind(7, bound_vendor_full_name).unwrap();
        let bound_src_mac: &str = &arp_packet.src_mac.to_string();
        statement.bind(8, bound_src_mac).unwrap();
        let bound_src_ip: &str = &arp_packet.src_ip.to_string();
        statement.bind(9, bound_src_ip).unwrap();
        let bound_tgt_mac: &str = &arp_packet.tgt_mac.to_string();
        statement.bind(10, bound_tgt_mac).unwrap();
        let bound_tgt_ip: &str = &arp_packet.tgt_ip.to_string();
        statement.bind(11, bound_tgt_ip).unwrap();
        statement.bind(12, operation).unwrap();
        statement.bind(13, matched).unwrap();
        statement.bind(14, netgrasp_event_src.timestamp).unwrap();
        statement.bind(15, netgrasp_event_src.timestamp).unwrap();
        statement.next().unwrap();
    }

    pub fn log_event(&self, netgrasp_event: &NetgraspEvent, event_type: &str) {
        // @TODO: network
        let network: &str = "";
        trace!("INSERT INTO event (mac_id, ip_id, vendor_id, interface, network, description, created, updated) VALUES({}, {}, {}, '{}', '{}', '{}', {}, {});",
            netgrasp_event.mac_id, netgrasp_event.ip_id, netgrasp_event.vendor_id, netgrasp_event.interface, network, event_type, netgrasp_event.timestamp, netgrasp_event.timestamp);
        let mut statement = self.sql.prepare("INSERT INTO event (mac_id, ip_id, vendor_id, interface, network, description, created, updated) VALUES(?, ?, ?, ?, ?, ?, ?, ?)").unwrap();
        statement.bind(1, netgrasp_event.mac_id).unwrap();
        statement.bind(2, netgrasp_event.ip_id).unwrap();
        statement.bind(3, netgrasp_event.vendor_id).unwrap();
        let bound_interface: &str = &netgrasp_event.interface;
        statement.bind(4, bound_interface).unwrap();
        let bound_network: &str = &network;
        statement.bind(5, bound_network).unwrap();
        let bound_description: &str = &event_type;
        statement.bind(6, bound_description).unwrap();
        statement.bind(7, netgrasp_event.timestamp).unwrap();
        statement.bind(8, netgrasp_event.timestamp).unwrap();
        statement.next().unwrap();
    }

    // Creates all the necessary tables and indexes, if not already existing.
    pub fn create_database(&self) {
        // Track each MAC address seen.
        self.sql.execute(
            "CREATE TABLE IF NOT EXISTS mac (
                mac_id  INTEGER PRIMARY KEY,
                vendor_id  INTEGER,
                address TEXT,
                is_self INTEGER,
                created TIMESTAMP,
                updated TIMESTAMP
            )").unwrap();
        self.sql.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address)").unwrap();

        // Track each IP address seen.
        self.sql.execute(
            "CREATE TABLE IF NOT EXISTS ip (
                ip_id INTEGER PRIMARY KEY,
                mac_id INTEGER,
                address TEXT,
                host_name TEXT,
                custom_name TEXT,
                created TIMESTAMP,
                updated TIMESTAMP
            )").unwrap();
        self.sql.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxip_address_macid ON mac (address, mac_id)").unwrap();
        //self.sql.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxip_macid_ipid ON ip (ip_id, mac_id)").unwrap();
        //self.sql.execute("CREATE INDEX IF NOT EXISTS idxip_address_mid_created ON ip (address, mac_id, created)").unwrap();
        //self.sql.execute("CREATE INDEX IF NOT EXISTS idxip_macid_ipid ON ip (mac_id, ip_id)").unwrap();

        self.sql.execute(
            "CREATE TABLE IF NOT EXISTS vendor(
                vendor_id INTEGER PRIMARY KEY,
                name TEXT,
                full_name TEXT,
                created TIMESTAMP,
                updated TIMESTAMP
            )").unwrap();
        self.sql.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxname_fullname ON vendor (name, full_name)").unwrap();

        // Log full details about each ARP packet seen.
        self.sql.execute(
            "CREATE TABLE IF NOT EXISTS arp (
                arp_id INTEGER PRIMARY KEY,
                src_mac_id INTEGER,
                src_ip_id INTEGER,
                tgt_ip_id INTEGER,
                interface TEXT,
                host_name TEXT,
                custom_name TEXT,
                vendor_name TEXT,
                vendor_full_name TEXT,
                src_mac TEXT,
                src_ip TEXT,
                tgt_mac TEXT,
                tgt_ip TEXT,
                operation INTEGER,
                matched INTEGER,
                created TIMESTAMP,
                updated TIMESTAMP
            )").unwrap();
        self.sql.execute("CREATE INDEX IF NOT EXISTS idxarp_int_src_tgt_op ON arp (interface, src_mac_id, src_ip_id, tgt_ip_id, operation)").unwrap();

        // Track events, allow notifications to be sent.
        self.sql.execute(
            "CREATE TABLE IF NOT EXISTS event (
                event_id INTEGER PRIMARY KEY,
                mac_id INTEGER,
                ip_id INTEGER,
                vendor_id INTEGER,
                interface TEXT,
                network TEXT,
                description TEXT,
                processed INTEGER,
                created TIMESTAMP,
                updated TIMESTAMP
            )").unwrap();
        //self.sql.execute("CREATE INDEX IF NOT EXISTS idxevent_description_timestamp_processed ON event (description, timestamp, processed)").unwrap();
        //self.sql.execute("CREATE INDEX IF NOT EXISTS idxevent_timestamp_processed ON event (timestamp, processed)").unwrap();
    }

    fn load_vendor_id(&self, mut netgrasp_event: NetgraspEvent) -> NetgraspEvent {
        trace!("SELECT vendor_id FROM vendor WHERE name = '{}' AND full_name = '{}';", &netgrasp_event.vendor_name, &netgrasp_event.vendor_full_name);
        let mut cursor = self.sql
            .prepare("SELECT vendor_id FROM vendor WHERE name = ? AND full_name = ?")
            .unwrap()
            .cursor();
        let bound_name = &netgrasp_event.vendor_name;
        let bound_full_name = &netgrasp_event.vendor_full_name;
        cursor.bind(&[
            Value::String(bound_name.to_string()),
            Value::String(bound_full_name.to_string()),
        ]).unwrap();

        // If this vendor exists, simply return the vendor_id.
        if let Some(row) = cursor.next().unwrap() {
            // Return the vendor_id.
            netgrasp_event.vendor_id = row[0].as_integer().unwrap();
            self.log_event(&netgrasp_event, EVENT_VENDOR_SEEN);
            netgrasp_event
        }
        // If this mac address doesn't exist, add it.
        else {
            // @TODO: trigger new_vendor event.
            info!("detected new vendor({} [{}])", &netgrasp_event.vendor_full_name, &netgrasp_event.vendor_name);

            trace!("INSERT INTO vendor (name, full_name, created, updated) VALUES('{}', '{}', {}, {});",
                &netgrasp_event.vendor_name, &netgrasp_event.vendor_full_name, netgrasp_event.timestamp, netgrasp_event.timestamp);
            let mut statement = self.sql.prepare("INSERT INTO vendor (name, full_name, created, updated) VALUES(?, ?, ?, ?)").unwrap();
            let bound_name: &str = &netgrasp_event.vendor_name;
            statement.bind(1, bound_name).unwrap();
            let bound_full_name: &str = &netgrasp_event.vendor_full_name;
            statement.bind(2, bound_full_name).unwrap();
            statement.bind(3, netgrasp_event.timestamp).unwrap();
            statement.bind(4, netgrasp_event.timestamp).unwrap();
            statement.next().unwrap();
            // Recursively determine the vendor_id we just added.
            netgrasp_event = self.load_vendor_id(netgrasp_event);
            self.log_event(&netgrasp_event, EVENT_VENDOR_SEEN_FIRST);
            netgrasp_event
        }
    }

    // Retreives mac_id of mac address, adding if not already seen.
    fn load_mac_id(&self, mut netgrasp_event: NetgraspEvent, mac_address: String, is_self: i64) -> NetgraspEvent {
        // @TODO: use the same text for debug and generating the actual query.
        trace!("SELECT mac_id, is_self FROM mac WHERE address = '{}';", &mac_address);
        let mut cursor = self.sql
            .prepare("SELECT mac_id, is_self FROM mac WHERE address = ?")
            .unwrap()
            .cursor();
        let bound_mac_address = &mac_address;
        cursor.bind(&[Value::String(bound_mac_address.to_string())]).unwrap();

        let formatted_mac_address = MacAddress::parse_str(&mac_address).unwrap();
        let vendor = self.oui.query_by_mac(&formatted_mac_address).unwrap();
        match vendor {
            Some(details) => {
                netgrasp_event.vendor_name = details.name_short;
                match details.name_long {
                    Some(name) => {
                        netgrasp_event.vendor_full_name = name;
                    }
                    None => {
                        netgrasp_event.vendor_full_name = netgrasp_event.vendor_name.clone();
                    }
                }
            }
            None => {
                // @TODO: Review these, perhaps perform a remote API call as a backup?
                netgrasp_event.vendor_name = "Unknown".to_string();
                netgrasp_event.vendor_full_name = "Unknown".to_string();
                info!("vendor lookup of mac_address({}) failed", &mac_address);
            }

        }
        // Look up vendor_id, creating if necessary.
        netgrasp_event = self.load_vendor_id(netgrasp_event);

        // If this mac address exists, simply return the mac_id.
        if let Some(row) = cursor.next().unwrap() {
            let existing_is_self = row[1].as_integer().unwrap();
            debug_assert!(existing_is_self == is_self);
            netgrasp_event.mac_id = row[0].as_integer().unwrap();
            self.log_event(&netgrasp_event, EVENT_MAC_SEEN);
            netgrasp_event
        }
        // If this mac address doesn't exist, add it.
        else {
            info!("detected new mac_address({}) with vendor({}) [{}]", &mac_address, &netgrasp_event.vendor_name, &netgrasp_event.vendor_full_name);
            trace!("INSERT INTO mac (address, is_self, vendor_id, created, updated) VALUES('{}', {}, {}, {}, {});", 
                &mac_address, is_self, netgrasp_event.vendor_id, netgrasp_event.timestamp, netgrasp_event.timestamp);
            let mut statement = self.sql.prepare("INSERT INTO mac (address, is_self, vendor_id, created, updated) VALUES(?, ?, ?, ?, ?)").unwrap();
            let bound_mac_address: &str = &mac_address;
            statement.bind(1, bound_mac_address).unwrap();
            statement.bind(2, is_self).unwrap();
            statement.bind(3, netgrasp_event.vendor_id).unwrap();
            statement.bind(4, netgrasp_event.timestamp).unwrap();
            statement.bind(5, netgrasp_event.timestamp).unwrap();
            statement.next().unwrap();
            // Recursively determine the mac_id of the mac address we just added.
            netgrasp_event = self.load_mac_id(netgrasp_event, mac_address, is_self);
            self.log_event(&netgrasp_event, EVENT_MAC_SEEN_FIRST);
            netgrasp_event
        }
    }

    // Retreives ip_id of ip address, adding if not already seen.
    pub fn load_ip_id(&self, mut netgrasp_event: NetgraspEvent, ip_address: String) -> NetgraspEvent {
        debug_assert!(ip_address != "0.0.0.0");

        let mut cursor;
        // If the IP address doesn't have an associated mac_id, see if we can query it from our database.
        if netgrasp_event.mac_id == 0 {
            // @TODO: if ip.address == ip.host_name, perhaps perform another reverse IP lookup.
            // @TODO: further, perhaps always perform a new reverse IP lookup every ~24 hours? Or,
            // simply respect the DNS ttl?
            trace!("SELECT ip_id, mac_id FROM ip WHERE address = '{}';", &ip_address);
            cursor = self.sql
                .prepare("SELECT ip_id, mac_id FROM ip WHERE address = ?")
                .unwrap()
                .cursor();
            let bound_ip_address = &ip_address;
            cursor.bind(&[Value::String(bound_ip_address.to_string())]).unwrap();
        }
        // While this IP address does have an associated mac_id, it may not yet be in our database (mac_id = 0).
        else {
            trace!("SELECT ip_id, mac_id FROM ip WHERE address = '{}' AND (mac_id = {} OR mac_id = 0);", &ip_address, netgrasp_event.mac_id);
            cursor = self.sql
                .prepare("SELECT ip_id, mac_id FROM ip WHERE address = ? AND (mac_id = ? OR mac_id = 0)")
                .unwrap()
                .cursor();
            let bound_ip_address = &ip_address;
            cursor.bind(&[Value::String(bound_ip_address.to_string()), Value::Integer(netgrasp_event.mac_id)]).unwrap();
        }

        // We have seen this IP before, return the ip_id.
        if let Some(row) = cursor.next().unwrap() {
            // While we've seen the IP before, we may not have seen the associated MAC address.
            if netgrasp_event.mac_id != 0 {
                let existing_mac_id = row[1].as_integer().unwrap();
                // We're seeing the MAC associated with this IP for the first time, update it.
                if existing_mac_id == 0 {
                    info!("UPDATE ip SET mac_id = {}, updated = {} WHERE address = '{}';",
                        netgrasp_event.mac_id, netgrasp_event.timestamp, &ip_address);
                    let mut cursor = self.sql
                        .prepare("UPDATE ip SET mac_id = ?, updated = ? WHERE address = ?")
                        .unwrap()
                        .cursor();
                    let bound_ip_address = &ip_address;
                    cursor.bind(&[
                        Value::Integer(netgrasp_event.mac_id),
                        Value::Integer(netgrasp_event.timestamp),
                        Value::String(bound_ip_address.to_string()),
                    ]).unwrap();
                    cursor.next().unwrap();
                    self.log_event(&netgrasp_event, EVENT_IP_SEEN_FIRST);
                }
            }
            // Return the ip_id.
            netgrasp_event.ip_id = row[0].as_integer().unwrap();
            if netgrasp_event.mac_id == 0 {
                self.log_event(&netgrasp_event, EVENT_IP_REQUEST);
            }
            else {
                self.log_event(&netgrasp_event, EVENT_IP_SEEN);
            }
        }
        // We're seeing this IP for the first time, add it to the database.
        else {
            let ip: std::net::IpAddr = ip_address.parse().unwrap();
            netgrasp_event.host_name = lookup_addr(&ip).unwrap();
            info!("detected new hostname({}) with (ip address, mac_id) pair: ({}, {})", &netgrasp_event.host_name, &ip_address, netgrasp_event.mac_id);

            trace!("INSERT INTO ip (address, mac_id, host_name, created, updated) VALUES('{}', {}, '{}', {}, {});",
                &ip_address, netgrasp_event.mac_id, &netgrasp_event.host_name, netgrasp_event.timestamp, netgrasp_event.timestamp);
            let mut statement = self.sql.prepare("INSERT INTO ip (address, mac_id, host_name, created, updated) VALUES(?, ?, ?, ?, ?)").unwrap();
            let bound_ip_address: &str = &ip_address;
            statement.bind(1, bound_ip_address).unwrap();
            statement.bind(2, netgrasp_event.mac_id).unwrap();
            let bound_host_name: &str = &netgrasp_event.host_name;
            statement.bind(3, bound_host_name).unwrap();
            statement.bind(4, netgrasp_event.timestamp).unwrap();
            statement.bind(5, netgrasp_event.timestamp).unwrap();
            statement.next().unwrap();
            // Recursively determine the ip_id of the IP address we just added.
            netgrasp_event = self.load_ip_id(netgrasp_event, ip_address);
            if netgrasp_event.mac_id == 0 {
                self.log_event(&netgrasp_event, EVENT_IP_REQUEST_FIRST);
            }
            else {
                self.log_event(&netgrasp_event, EVENT_IP_SEEN_FIRST);
            }
        }
        netgrasp_event
    }
}

// Python Netgrasp DB Schema:
//
//
// CREATE TABLE IF NOT EXISTS device(
//   did INTEGER PRIMARY KEY,
//   mid INTEGER,
//   iid INTEGER,
//   hid INTEGER,
//   vid INTEGER,
//   created TIMESTAMP,
//   updated TIMESTAMP
// )
// CREATE UNIQUE INDEX IF NOT EXISTS idxdevice_mid_iid ON device (mid, iid)
// CREATE INDEX IF NOT EXISTS idxdevice_hid_mid_did ON device (hid, mid, did)
// CREATE INDEX IF NOT EXISTS idxdevice_vid ON device (vid)
// CREATE INDEX IF NOT EXISTS idxdevice_updated ON device (updated)
//
// CREATE TABLE IF NOT EXISTS activity(
//   aid INTEGER PRIMARY KEY,
//   did INTEGER,
//   iid INTEGER,
//   interface TEXT,
//   network TEXT,
//   created TIMESTAMP,
//   updated TIMESTAMP,
//   counter INTEGER,
//   active INTEGER
// )
// CREATE INDEX IF NOT EXISTS idxactivity_active_did ON activity (active, did)
// CREATE INDEX IF NOT EXISTS idxactivity_did_iid ON activity (did, iid)
// CREATE INDEX IF NOT EXISTS idxactivity_did_active_counter ON activity (did, active, counter)
// CREATE INDEX IF NOT EXISTS idxactivity_active_updated ON activity (active, updated)
//
// CREATE TABLE IF NOT EXISTS request(
//   rid INTEGER PRIMARY KEY,
//   did INTEGER,
//   ip TEXT,
//   interface TEXT,
//   network TEXT,
//   created TIMESTAMP,
//   updated TIMESTAMP,
//   counter INTEGER,
//   active INTEGER
// )
// CREATE INDEX IF NOT EXISTS idxrequest_active_updated ON request (active, updated)
// CREATE INDEX IF NOT EXISTS idxrequest_updated ON request (updated)
// CREATE INDEX IF NOT EXISTS idxrequest_active_ip ON request (active, ip)
// CREATE INDEX IF NOT EXISTS idxrequest_did_created ON request (did, created)
//
// CREATE TABLE IF NOT EXISTS event(
//   eid INTEGER PRIMARY KEY,
//   mid INTEGER,
//   iid INTEGER,
//   did INTEGER,
//   rid INTEGER,
//   interface TEXT,
//   network TEXT,
//   timestamp TIMESTAMP,
//   processed INTEGER,
//   type VARCHAR
// )
// CREATE INDEX IF NOT EXISTS idxevent_type_timestamp_processed ON event (type, timestamp, processed)
// CREATE INDEX IF NOT EXISTS idxevent_timestamp_processed ON event (timestamp, processed)
// # PRAGMA index_list(event)
// ANALYZE
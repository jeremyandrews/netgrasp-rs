use smoltcp::wire::{ArpOperation};
use sqlite::Value;

// @TODO: Static cache .. can we only get the connection once?
pub fn get_database_connection() -> sqlite::Connection {
    sqlite::open("./netgrasp.db").unwrap()
}

pub fn create_database() {
    let connection = get_database_connection();

    // Track each MAC address seen.
    connection.execute(
        "CREATE TABLE IF NOT EXISTS mac (
            mac_id  INTEGER PRIMARY KEY,
            address TEXT,
            is_self INTEGER,
            created TIMESTAMP
        )").unwrap();
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address)").unwrap();

    // Track each IP address seen.
    connection.execute(
        "CREATE TABLE IF NOT EXISTS ip (
            ip_id INTEGER PRIMARY KEY,
            mac_id INTEGER,
            address TEXT,
            seen INTEGER,
            created TIMESTAMP
        )").unwrap();
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxip_address_macid ON mac (address, mac_id)").unwrap();
    //connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxip_macid_ipid ON ip (ip_id, mac_id)").unwrap();
    //connection.execute("CREATE INDEX IF NOT EXISTS idxip_address_mid_created ON ip (address, mac_id, created)").unwrap();
    //connection.execute("CREATE INDEX IF NOT EXISTS idxip_macid_ipid ON ip (mac_id, ip_id)").unwrap();

    // Log full details about each ARP packet seen.
    connection.execute(
        "CREATE TABLE IF NOT EXISTS arp (
            arp_id INTEGER PRIMARY KEY,
            interface TEXT,
            src_mac_id INTEGER,
            src_ip_id INTEGER,
            tgt_mac_id INTEGER,
            tgt_ip_id INTEGER,
            operation INTEGER,
            matched INTEGER,
            timestamp TIMESTAMP
        )").unwrap();
    connection.execute("CREATE INDEX IF NOT EXISTS idxarp_int_src_tgt_op ON arp (interface, src_mac_id, src_ip_id, tgt_mac_id, tgt_ip_id, operation)").unwrap();
}

// Find address in mac table, adding if not there yet, returning mac_id.
pub fn get_mac_id(mac_address: String, is_self: i64) -> i64 {
    let connection = get_database_connection();
    // @TODO: Determine if this is our MAC, or an external MAC (and update table accordignly).

    trace!("SELECT mac_id, is_self FROM mac WHERE address = '{}';", &mac_address);
    let mut cursor = connection
        .prepare("SELECT mac_id, is_self FROM mac WHERE address = ?")
        .unwrap()
        .cursor();
    let bound_mac_address = &mac_address;
    cursor.bind(&[Value::String(bound_mac_address.to_string())]).unwrap();

    // This mac address already exists, return its mac_id.
    if let Some(row) = cursor.next().unwrap() {
        let existing_is_self = row[1].as_integer().unwrap();
        debug_assert!(existing_is_self == is_self);
        row[0].as_integer().unwrap()
    }
    // This mac address doesn't exist yet, add it then recursively return its mac_id.
    else {
        trace!("INSERT INTO mac (address, is_self) VALUES('{}', {});", &mac_address, is_self);
        let mut statement = connection.prepare("INSERT INTO mac (address, is_self) VALUES(?, ?)").unwrap();
        let bound_mac_address: &str = &mac_address;
        statement.bind(1, bound_mac_address).unwrap();
        statement.bind(2, is_self).unwrap();
        statement.next().unwrap();
        // @TODO: trigger new_mac event.
        info!("detected new mac_address: {}", &mac_address);
        get_mac_id(mac_address, is_self)
    }
}

pub fn get_ip_id(ip_address: String, mac_id: i64, seen: bool) -> i64 {
    let connection = get_database_connection();

    trace!("SELECT ip_id, seen FROM ip WHERE address = '{}' AND (mac_id = {} OR mac_id = 0);", &ip_address, mac_id);
    let mut cursor = connection
        .prepare("SELECT ip_id, seen FROM ip WHERE address = ? AND (mac_id = ? OR mac_id = 0)")
        .unwrap()
        .cursor();
    let bound_ip_address = &ip_address;
    cursor.bind(&[Value::String(bound_ip_address.to_string()), Value::Integer(mac_id)]).unwrap();

    if let Some(row) = cursor.next().unwrap() {
        // This ip address mac_id pair already exists, return ip_id.
        if seen {
            let existing_seen = row[1].as_integer().unwrap();
            if existing_seen == 0 {
                // We've now seen an IP that was only requested before
                info!("UPDATE ip SET seen = 1, mac_id = {} WHERE address = '{}';", mac_id, &ip_address);
                let mut cursor = connection
                    .prepare("UPDATE ip SET seen = 1, mac_id = ? WHERE address = ?")
                    .unwrap()
                    .cursor();
                let bound_ip_address = &ip_address;
                cursor.bind(&[Value::Integer(mac_id), Value::String(bound_ip_address.to_string())]).unwrap();
                cursor.next().unwrap();
            }
        }
        row[0].as_integer().unwrap()
    }
    else {
        // This ip address / mac_id pair doesn't exist yet, add it then recursively return ip_id.
        trace!("INSERT INTO ip (address, mac_id, seen) VALUES('{}', {}, {});", &ip_address, mac_id, seen as i64);
        let mut statement = connection.prepare("INSERT INTO ip (address, mac_id, seen) VALUES(?, ?, ?)").unwrap();
        let bound_ip_address: &str = &ip_address;
        statement.bind(1, bound_ip_address).unwrap();
        statement.bind(2, mac_id).unwrap();
        statement.bind(3, seen as i64).unwrap();
        statement.next().unwrap();
        // @TODO: trigger new_ip event.
        info!("detected new (ip address, mac_id) pair: ({}, {})", &ip_address, mac_id);
        get_ip_id(ip_address, mac_id, seen)
    }
}

pub fn log_arp_packet(arp_packet: crate::net::arp::NetgraspArpPacket) {
    trace!("log_arp_packet: {:?}", arp_packet);

    let mut src_mac_id: i64 = 0;
    let mut tgt_ip_id: i64 = 0;
    let src_ip_id: i64;

    match arp_packet.operation {
        ArpOperation::Request => {
            trace!("ARP request");
            // don't log source mac broadcast as it isn't an actual, valid MAC
            if arp_packet.src_is_broadcast {
                debug!("ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
            }
            // log all other source mac addresses
            else {
                src_mac_id = get_mac_id(arp_packet.src_mac.to_string(), arp_packet.src_is_self as i64);
            }

            if arp_packet.src_ip != arp_packet.tgt_ip && arp_packet.src_mac != arp_packet.tgt_mac {
                if arp_packet.tgt_is_broadcast {
                    debug!("ignoring arp broadcast target of {} [{}]", arp_packet.tgt_ip, arp_packet.tgt_mac)
                }
                else {
                    debug!("logging tgt_mac");
                    tgt_ip_id = get_ip_id(arp_packet.tgt_ip.to_string(), arp_packet.tgt_is_self as i64, false);
                }
            }

        }
        ArpOperation::Reply => {
            trace!("ARP reply");
            // don't log source mac broadcast as it isn't an actual, valid MAC
            if arp_packet.src_is_broadcast {
                debug!("ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
            }
            // log all other source mac addresses
            else {
                src_mac_id = get_mac_id(arp_packet.src_mac.to_string(), arp_packet.src_is_self as i64);
            }
        }
        _ => {
            debug!("invalid ARP packet")
        }
    }

    if src_mac_id != 0 {
        debug!("source mac_id: {}", src_mac_id);
        if arp_packet.src_ip.to_string() == "0.0.0.0" {
            debug!("ignoring arp ip source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
        }
        else {
            src_ip_id = get_ip_id(arp_packet.src_ip.to_string(), src_mac_id, true);
            debug!("source ip_id: {}", src_ip_id);
        }
    }

    if tgt_ip_id != 0 {
        debug!("target ip_id: {}", tgt_ip_id);
    }

    // @TODO: log ARP
    // @TODO: if Response, match to Request
}

// Python Netgrasp DB Schema:
//
// CREATE TABLE IF NOT EXISTS mac(
//   mid INTEGER PRIMARY KEY,
//   vid TEXT,
//   address TEXT,
//   created TIMESTAMP,
//   self INTEGER
// )
// CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address)
// CREATE INDEX IF NOT EXISTS idxmac_vid ON mac (vid)
//
// CREATE TABLE IF NOT EXISTS vendor(
//   vid INTEGER PRIMARY KEY,
//   name VARCHAR UNIQUE,
//   created TIMESTAMP
// )
//
// CREATE TABLE IF NOT EXISTS ip(
//   iid INTEGER PRIMARY KEY,
//   mid INTEGER,
//   address TEXT,
//   created TIMESTAMP
// )
// CREATE UNIQUE INDEX IF NOT EXISTS idxip_mid_iid ON ip (mid, iid)
// CREATE INDEX IF NOT EXISTS idxip_address_mid_created ON ip (address, mid, created)
// CREATE INDEX IF NOT EXISTS idxip_mid_iid ON ip (mid, iid)
//
// CREATE TABLE IF NOT EXISTS host(
//   hid INTEGER PRIMARY KEY,
//   iid INTEGER,
//   name TEXT,
//   custom_name TEXT,
//   created TIMESTAMP,
//   updated TIMESTAMP
//)
// CREATE UNIQUE INDEX IF NOT EXISTS idxhost_iid ON host (iid)
// CREATE INDEX IF NOT EXISTS idxhost_name ON host (name)
// CREATE INDEX IF NOT EXISTS idxhost_custom ON host (custom_name)
// CREATE INDEX IF NOT EXISTS idxhost_updated ON host (updated)
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
// CREATE TABLE IF NOT EXISTS arp(
//   aid INTEGER PRIMARY KEY,
//   did INT,
//   src_mac TEXT,
//   src_ip TEXT,
//   rid INT,
//   dst_mac TEXT,
//   dst_ip TEXT,
//   interface TEXT,
//   network TEXT,
//   timestamp TIMESTAMP
// )
// CREATE INDEX IF NOT EXISTS idxarp_srcip_timestamp_rid ON arp (src_ip, timestamp, rid)
// CREATE INDEX IF NOT EXISTS idxarp_rid_srcip ON arp (rid, src_ip)
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
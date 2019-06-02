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
            created TIMESTAMP,
            self    NUMERIC
        )").unwrap();
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address)").unwrap();

    // Track each IP address seen.
    connection.execute(
        "CREATE TABLE IF NOT EXISTS ip (
            ip_id INTEGER PRIMARY KEY,
            mac_id INTEGER,
            address TEXT,
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
pub fn get_mac_id(mac_address: String) -> i64 {
    let connection = get_database_connection();
    // @TODO: Determine if this is our MAC, or an external MAC (and update table accordignly).

    trace!("SELECT mac_id FROM mac WHERE address = '{}';", &mac_address);
    let mut cursor = connection
        .prepare("SELECT mac_id FROM mac WHERE address = ?")
        .unwrap()
        .cursor();
    let bound_mac_address = &mac_address;
    cursor.bind(&[Value::String(bound_mac_address.to_string())]).unwrap();

    if let Some(row) = cursor.next().unwrap() {
        // This mac address already exists, return its mac_id.
        row[0].as_integer().unwrap()
    }
    else {
        // This mac address doesn't exist yet, add it then recursively return its mac_id.
        trace!("INSERT INTO mac (address) VALUES('{}');", &mac_address);
        let mut statement = connection.prepare("INSERT INTO mac (address) VALUES(?)").unwrap();
        let bound_mac_address: &str = &mac_address;
        statement.bind(1, bound_mac_address).unwrap();
        statement.next().unwrap();
        // @TODO: trigger new_mac event.
        info!("detected new mac_address: {}", &mac_address);
        get_mac_id(mac_address)
    }
}

pub fn get_ip_id(ip_address: String, mac_id: i64) -> i64 {
    let connection = get_database_connection();

    trace!("SELECT ip_id FROM ip WHERE address = '{}' AND mac_id = {};", &ip_address, mac_id);
    let mut cursor = connection
        .prepare("SELECT ip_id FROM ip WHERE address = ? AND mac_id = ?")
        .unwrap()
        .cursor();
    let bound_ip_address = &ip_address;
    cursor.bind(&[Value::String(bound_ip_address.to_string()), Value::Integer(mac_id)]).unwrap();

    if let Some(row) = cursor.next().unwrap() {
        // This ip address mac_id pair already exists, return ip_id.
        row[0].as_integer().unwrap()
    }
    else {
        // This ip address / mac_id piar doesn't exist yet, add it then recursively return ip_id.
        trace!("INSERT INTO ip (address, mac_id) VALUES('{}', {});", &ip_address, mac_id);
        let mut statement = connection.prepare("INSERT INTO ip (address, mac_id) VALUES(?, ?)").unwrap();
        let bound_ip_address: &str = &ip_address;
        statement.bind(1, bound_ip_address).unwrap();
        statement.bind(2, mac_id).unwrap();
        statement.next().unwrap();
        // @TODO: trigger new_ip event.
        info!("detected new (ip address, mac_id) pair: ({}, {})", &ip_address, mac_id);
        get_ip_id(ip_address, mac_id)
    }
}

pub fn log_arp_packet(arp_packet: crate::net::arp::NetgraspArpPacket) {
    match arp_packet.operation {
        ArpOperation::Request => {
            debug!("detected ARP request");
        }
        ArpOperation::Reply => {
            debug!("detected ARP reply");
        }
        _ => {
            debug!("detected invalid ARP packet")
        }
    }

    trace!("{:?}", arp_packet);
    // @TODO: determine if we're logging src or tgt (or both?) here
    let mac_id = get_mac_id(arp_packet.src_mac.to_string());
    debug!("mac_id: {}", mac_id);

    let ip_id = get_ip_id(arp_packet.src_ip.to_string(), mac_id);
    debug!("ip_id: {}", ip_id);

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
//   self NUMERIC
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
//   counter NUMERIC,
//   active NUMERIC
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
//   counter NUMERIC,
//   active NUMERIC
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
//   processed NUMERIC,
//   type VARCHAR
// )
// CREATE INDEX IF NOT EXISTS idxevent_type_timestamp_processed ON event (type, timestamp, processed)
// CREATE INDEX IF NOT EXISTS idxevent_timestamp_processed ON event (timestamp, processed)
// # PRAGMA index_list(event)
// ANALYZE
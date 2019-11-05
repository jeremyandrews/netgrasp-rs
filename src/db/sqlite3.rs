use diesel::prelude::*;
use diesel::sql_types::{Text, Integer};
use diesel::{sql_query, debug_query};
use diesel_migrations::{run_pending_migrations, RunMigrationsError};
use diesel::sqlite::Sqlite;
use dns_lookup::{lookup_addr};
use eui48::MacAddress;
use oui::OuiDatabase;
use crate::db::models::*;
use crate::utils::{time, format};
use crate::notifications::templates;
use rqpush::Notification;
use smoltcp::wire::ArpOperation;

// IPs are considered active for 3 hours
pub const IPS_ACTIVE_FOR: u64 = 10800;

// Limit the number of devices to list when listing devices talked to
pub const TALKED_TO_LIMIT: i64 = 50;

pub struct NetgraspDb {
    sql: SqliteConnection,
    oui: OuiDatabase,
}

#[derive(Debug, Queryable)]
pub struct NetgraspEvent {
    timestamp: i32,
    interface: String,
    mac_id: i32,
    mac_address: String,
    is_self: i32,
    ip_id: i32,
    ip_address: String,
    event_type: String,
    event_description: String,
    host_name: String,
    custom_name: String,
    vendor_id: i32,
    vendor_name: String,
    vendor_full_name: String,
}

#[derive(Debug, Default, Queryable)]
pub struct NetgraspActiveDevice {
    pub interface: String,
    pub ip_address: String,
    pub mac_address: String,
    pub host_name: String,
    pub vendor_name: String,
    pub vendor_full_name: String,
    pub custom_name: String,
    pub recently_seen_count: i64,
    pub recently_seen_first: i32,
    pub recently_seen_last: i32,
}

#[derive(Debug, Default, PartialEq, Queryable)]
pub struct TalkedTo {
    pub ip_address: String,
    pub mac_address: String,
}

#[derive(Debug, Queryable, QueryableByName)]
pub struct DistinctIpId {
    #[sql_type = "Integer"]
    pub src_ip_id: i32,
}


#[derive(Debug, Queryable, QueryableByName)]
pub struct TalkedToCount {
    #[sql_type = "Integer"]
    pub counter: i32,
}

#[derive(Debug, Default, Queryable, QueryableByName)]
pub struct NetworkScan {
    #[sql_type = "Integer"]
    pub tgt_ip_id_count: i32,
    #[sql_type = "Integer"]
    pub src_ip_id: i32,
}

#[derive(Debug, Clone)]
enum NetgraspEventType {
    Undeclared,
    VendorFirstSeen,
    VendorSeen,
    MacFirstSeen,
    MacSeen,
    //MacDuplicate,
    //MacBroadcast,
    IpFirstRequest,
    IpRequest,
    //IpRequestSelf,
    IpFirstSeen,
    IpSeen,
    IpInactive,
    IpReturned,
    //IpChanged,
    //IpDuplicate,
    //IpNotOnNetwork,
    DeviceFirstSeen,
    DeviceSeen,
    DeviceInactive,
    DeviceReturned,
    NetworkScan,
}

struct NetgraspEventDetail {
    name: String,
    description: String,
    priority: u8,
}

fn netgrasp_event_detail(netgrasp_event_type: NetgraspEventType) -> NetgraspEventDetail {
    match netgrasp_event_type {
        NetgraspEventType::Undeclared => NetgraspEventDetail {
            name: "undeclared event".to_string(),
            description: "Undeclared network event".to_string(),
            priority: 0,
        },
        NetgraspEventType::MacSeen => NetgraspEventDetail {
            name: "mac seen".to_string(),
            description: "Nac address on network".to_string(),
            priority: 3,
        },
        /*
        NetgraspEventType::MacBroadcast => NetgraspEventDetail {
            name: "mac broadcast".to_string(),
            description: "Mac broadcast on network".to_string(),
            priority: 3,
        },
        */
        NetgraspEventType::IpRequest => NetgraspEventDetail {
            name: "IP requested".to_string(),
            description: "Requested mac address of an IP on network".to_string(),
            priority: 5,
        },
        NetgraspEventType::IpSeen => NetgraspEventDetail {
            name: "IP seen".to_string(),
            description: "IP on network".to_string(),
            priority: 6,
        },
        NetgraspEventType::VendorSeen => NetgraspEventDetail {
            name: "vendor seen".to_string(),
            description: "Vendor on network".to_string(),
            priority: 8,
        },
        NetgraspEventType::DeviceSeen => NetgraspEventDetail {
            name: "device seen".to_string(),
            description: "Device on network".to_string(),
            priority: 12,
        },
        /*
        NetgraspEventType::IpRequestSelf => NetgraspEventDetail {
            name: "IP requested self".to_string(),
            description: "Mac address associated with IP requested self".to_string(),
            priority: 20,
        },
        */
        NetgraspEventType::VendorFirstSeen => NetgraspEventDetail {
            name: "new vendor".to_string(),
            description: "New vendor on network".to_string(),
            priority: 100,
        },
        NetgraspEventType::IpInactive => NetgraspEventDetail {
            name: "IP inactive".to_string(),
            description: "IP on network has gone inactive".to_string(),
            priority: 100,
        },
        NetgraspEventType::IpFirstRequest => NetgraspEventDetail {
            name: "new IP requested".to_string(),
            description: "Requested mac address of a new IP on network".to_string(),
            priority: 110,
        },
        NetgraspEventType::DeviceInactive => NetgraspEventDetail {
            name: "device inactive".to_string(),
            description: "Device on network has gone inactive".to_string(),
            priority: 110,
        },
        NetgraspEventType::MacFirstSeen => NetgraspEventDetail {
            name: "new mac".to_string(),
            description: "New mac address on network".to_string(),
            priority: 120,
        },
        NetgraspEventType::IpFirstSeen => NetgraspEventDetail {
            name: "new IP".to_string(),
            description: "New IP on network".to_string(),
            priority: 125,
        },
        NetgraspEventType::IpReturned => NetgraspEventDetail {
            name: "IP returned".to_string(),
            description: "Inactive IP on network returned".to_string(),
            priority: 125,
        },
        /*
        NetgraspEventType::IpChanged => NetgraspEventDetail {
            name: "IP changed".to_string(),
            description: "IP address changed".to_string(),
            priority: 140,
        },
        NetgraspEventType::IpDuplicate => NetgraspEventDetail {
            name: "duplicate IP".to_string(),
            description: "Duplicate IP on network".to_string(),
            priority: 140,
        },
        NetgraspEventType::IpNotOnNetwork => NetgraspEventDetail {
            name: "IP not on network".to_string(),
            description: "IP not on network".to_string(),
            priority: 140,
        },
        NetgraspEventType::MacDuplicate => NetgraspEventDetail {
            name: "Duplicate mac".to_string(),
            description: "Duplicate mac addresses on network".to_string(),
            priority: 150,
        },
        */
        NetgraspEventType::DeviceFirstSeen => NetgraspEventDetail {
            name: "new device".to_string(),
            description: "New device on network".to_string(),
            priority: 150,
        },
        NetgraspEventType::DeviceReturned => NetgraspEventDetail {
            name: "device returned".to_string(),
            description: "Inactive device returned to network".to_string(),
            priority: 150,
        },
        NetgraspEventType::NetworkScan => NetgraspEventDetail {
            name: "network scan".to_string(),
            description: "Device performed a network scan".to_string(),
            priority: 150,
        },
    }
}

fn get_device_name(netgrasp_event: &NetgraspEvent) -> String {
    format::device_name(format::DeviceName {
        custom_name: netgrasp_event.custom_name.to_string(),
        host_name: netgrasp_event.host_name.to_string(),
        ip_address: netgrasp_event.ip_address.to_string(),
        vendor_full_name: netgrasp_event.vendor_full_name.to_string(),
    })
}

impl NetgraspEvent {
    pub fn new(interface: String) -> Self {
        let event_detail = netgrasp_event_detail(NetgraspEventType::Undeclared);
        NetgraspEvent {
            timestamp: time::timestamp_now() as i32,
            interface: interface,
            mac_id: 0,
            mac_address: "".to_string(),
            is_self: 0,
            ip_id: 0,
            ip_address: "".to_string(),
            event_type: event_detail.name,
            event_description: event_detail.description,
            host_name: "".to_string(),
            custom_name: "".to_string(),
            vendor_id: 0,
            vendor_name: "".to_string(),
            vendor_full_name: "".to_string(),
        }
    }
}

impl NetgraspDb {
    pub fn new(sql_database_path: String, oui_database_path: String) -> Self {
        NetgraspDb {
            sql: NetgraspDb::establish_sqlite_connection(&sql_database_path),
            oui: NetgraspDb::establish_oui_connection(&oui_database_path),
        }
    }

    fn establish_sqlite_connection(sqlite_database_path: &str) -> SqliteConnection {
        info!("establishing connection to SQLite database: [{}]", sqlite_database_path);
        let sql_connection = match SqliteConnection::establish(sqlite_database_path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to establish SQLite connection: [{}]", e);
                std::process::exit(1);
            }
        };
        sql_connection
    }

    fn establish_oui_connection(oui_database_path: &str) -> OuiDatabase {
        info!("establishing connection to OUI database: [{}]", oui_database_path);
        let oui_connection = match OuiDatabase::new_from_file(oui_database_path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to establish OUI database connection: [{}]", e);
                std::process::exit(1);
            }
        };
        oui_connection
    }

    pub fn migrate(&self) -> std::result::Result<(), RunMigrationsError> {
        run_pending_migrations(&self.sql)
    }

    // Returns a vector of all currently known active devices.
    pub fn get_active_devices(&self) -> Vec<NetgraspActiveDevice> {
        use crate::db::schema::arp::dsl::*;
        use crate::db::schema::ip;

        let min_updated = diesel::dsl::sql::<diesel::sql_types::Integer>("MIN(arp.updated)");
        let max_updated = diesel::dsl::sql::<diesel::sql_types::Integer>("MAX(arp.updated)");
        let count_src_ip = diesel::dsl::sql::<diesel::sql_types::BigInt>("COUNT(src_ip)");
        let active_devices_query = arp
            .inner_join(ip::table)
            .select((interface, src_ip, src_mac, host_name, vendor_name, vendor_full_name, ip::custom_name, &count_src_ip, min_updated, &max_updated))
            .filter(src_ip.ne("0.0.0.0"))
            .filter(is_active.eq(1))
            .group_by(src_ip)
            .order((max_updated.clone().desc(), count_src_ip.clone().desc()));
        debug!("get_active_devices: {}", debug_query::<Sqlite, _>(&active_devices_query).to_string());
        let active_devices: Vec<(NetgraspActiveDevice)> = match active_devices_query.load(&self.sql) {
            Ok(a) => a,
            Err(e) => {
                error!("Error loading active devices: [{}]", e);
                vec!(NetgraspActiveDevice::default())
            }
        };
        debug!("get_active_devices: {} active devices", active_devices.len());
        active_devices
    }

    // Record each ARP packet we see.
    pub fn log_arp_packet(&self, arp_packet: crate::net::arp::NetgraspArpPacket) {
        use crate::db::schema::arp;

        trace!("log_arp_packet: {:?}", arp_packet);

        let operation: i32;
        // Object used to create events for the source side of the ARP message.
        let mut netgrasp_event_src = NetgraspEvent::new(arp_packet.interface.clone());
        // Object used to create events for the target side of the ARP message.
        let mut netgrasp_event_tgt = NetgraspEvent::new(arp_packet.interface.clone());

        match arp_packet.operation {
            ArpOperation::Request => {
                trace!("log_arp_packet: ARP request");
                // A MAC broadcast isn't a real MAC address, so don't store it.
                if arp_packet.src_is_broadcast {
                    debug!("log_arp_packet: ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
                }
                // Log all non-broadcast mac addresses.
                else {
                    netgrasp_event_src = self.load_mac_id(netgrasp_event_src, arp_packet.src_mac.to_string(), arp_packet.src_is_self as i32);
                }

                if arp_packet.src_ip != arp_packet.tgt_ip && arp_packet.src_mac != arp_packet.tgt_mac {
                    // A MAC broadcast isn't a real MAC address, so don't store it.
                    if arp_packet.tgt_is_broadcast {
                        debug!("log_arp_packet: ignoring arp broadcast target of {} [{}]", arp_packet.tgt_ip, arp_packet.tgt_mac)
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
                    debug!("log_arp_packet: ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
                }
                // Log all non-broadcast mac addresses.
                else {
                    netgrasp_event_src = self.load_mac_id(netgrasp_event_src, arp_packet.src_mac.to_string(), arp_packet.src_is_self as i32);
                }
                operation = 1;
            }
            _ => {
                info!("log_arp_packet: invalid ARP packet: {:?}", arp_packet);
                operation = -1;
            }
        }

        // We have a valid MAC address to associate with the IP address.
        if netgrasp_event_src.mac_id != 0 {
            debug!("log_arp_packet: source mac_id: {}", netgrasp_event_src.mac_id);
            // We don't record the broadcast of 0.0.0.0.
            if arp_packet.src_ip.to_string() == "0.0.0.0" {
                debug!("log_arp_packet: ignoring arp ip source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
            }
            // Record all other addresses.
            else {
                netgrasp_event_src = self.load_ip_id(netgrasp_event_src, arp_packet.src_ip.to_string());
                debug!("log_arp_packet: source ip_id: {}", netgrasp_event_src.ip_id);
            }
        }

        // We recorded the target IP in our database.
        if netgrasp_event_tgt.ip_id != 0 {
            debug!("log_arp_packet: target ip_id: {}", netgrasp_event_tgt.ip_id);
        }

        let new_arp = NewArp {
            src_mac_id: netgrasp_event_src.mac_id,
            src_ip_id: netgrasp_event_src.ip_id,
            src_vendor_id: netgrasp_event_src.vendor_id,
            tgt_ip_id: netgrasp_event_tgt.ip_id,
            interface: arp_packet.interface,
            host_name: netgrasp_event_src.host_name,
            custom_name: netgrasp_event_src.custom_name,
            vendor_name: netgrasp_event_src.vendor_name,
            vendor_full_name: netgrasp_event_src.vendor_full_name,
            src_mac: arp_packet.src_mac.to_string(),
            src_ip: arp_packet.src_ip.to_string(),
            tgt_mac: arp_packet.tgt_mac.to_string(),
            tgt_ip: arp_packet.tgt_ip.to_string(),
            operation: operation,
            is_self: netgrasp_event_src.is_self,
            is_active: 1,
            processed: 0,
            matched: 0,
            event_type: netgrasp_event_src.event_type,
            event_description: netgrasp_event_src.event_description,
            created: netgrasp_event_src.timestamp,
            updated: netgrasp_event_src.timestamp
        };

        let insert_arp_query = diesel::insert_into(arp::table)
            .values(&new_arp);
        debug!("log_arp_packet: log_arp_packet: {}", debug_query::<Sqlite, _>(&insert_arp_query).to_string());
        match insert_arp_query.execute(&self.sql) {
            Ok(_) => (),
            Err(e) => error!("log_arp_packet: failed to write arp packet to database: [{}]", e),
        }
    }

    fn load_vendor_id(&self, mut netgrasp_event: NetgraspEvent) -> NetgraspEvent {
        use crate::db::schema::vendor;

        let vendor_query = vendor::table
            .filter(vendor::name.eq(&netgrasp_event.vendor_name))
            .filter(vendor::full_name.eq(&netgrasp_event.vendor_full_name));
        debug!("load_vendor_id: {}", debug_query::<Sqlite, _>(&vendor_query).to_string());
        match vendor_query.get_result::<Vendor>(&self.sql) {
            // If the vendor exists, return vendor_id.
            Ok(v) => {
                netgrasp_event.vendor_id = v.vendor_id;
                netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::VendorSeen, &v.full_name);
                netgrasp_event
            }
            // Otherwise this is the first time we've seen this vendor.
            Err(_) => {
                // If this mac address doesn't exist, add it.
                info!("detected new vendor({} [{}])", &netgrasp_event.vendor_full_name, &netgrasp_event.vendor_name);
                let new_vendor = NewVendor {
                    name: netgrasp_event.vendor_name.to_string(),
                    full_name: netgrasp_event.vendor_full_name.to_string(),
                    created: netgrasp_event.timestamp,
                    updated: netgrasp_event.timestamp,
                };
                let insert_vendor_query = diesel::insert_into(vendor::table)
                    .values(&new_vendor);
                debug!("load_vendor_id: insert new vendor: {}", debug_query::<Sqlite, _>(&insert_vendor_query).to_string());
                match insert_vendor_query.execute(&self.sql) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Error inserting vendor into database: [{}]", e);
                        // We have to exit or we'll get into an infinite loop.
                        std::process::exit(1);
                    }
                }

                // Recursively determine the vendor_id we just added.
                // @TODO: can we get that from our earlier insert?
                netgrasp_event = self.load_vendor_id(netgrasp_event);
                let vendor_full_name = netgrasp_event.vendor_full_name.to_string();
                netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::VendorFirstSeen, &vendor_full_name);
                netgrasp_event
            }
        }
    }

    // Retreives mac_id of mac address, adding if not already seen.
    fn load_mac_id(&self, mut netgrasp_event: NetgraspEvent, mac_address: String, is_self: i32) -> NetgraspEvent {
        use crate::db::schema::mac;

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
                netgrasp_event.vendor_name = "unknown".to_string();
                netgrasp_event.vendor_full_name = "unknown".to_string();
                debug!("vendor lookup of mac_address({}) failed", &mac_address);
            }

        }
        // Look up vendor_id, creating if necessary.
        netgrasp_event = self.load_vendor_id(netgrasp_event);

        let mac_query = mac::table
            .filter(mac::address.eq(&mac_address));
        debug!("load_mac_id: {}", debug_query::<Sqlite, _>(&mac_query).to_string());
        match mac_query.get_result::<Mac>(&self.sql) {
            // If the mac exists, return mac_id.
            Ok(m) => {
                let existing_is_self = m.is_self;
                debug_assert!(existing_is_self == is_self);
                netgrasp_event.mac_id = m.mac_id;
                netgrasp_event.mac_address = mac_address.clone();
                netgrasp_event.is_self = is_self;
                netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::MacSeen, &mac_address);
                netgrasp_event
            }
            // Otherwise this is the first time we've seen this vendor.
            Err(_) => {
                // If this mac address doesn't exist, add it.
                info!("detected new mac_address({}) with vendor({}) [{}]", &mac_address, &netgrasp_event.vendor_name, &netgrasp_event.vendor_full_name);
                trace!("INSERT INTO mac (address, is_self, vendor_id, created, updated) VALUES('{}', {}, {}, {}, {});", 
                    &mac_address, is_self, netgrasp_event.vendor_id, netgrasp_event.timestamp, netgrasp_event.timestamp);

                let new_mac = NewMac {
                    vendor_id: netgrasp_event.vendor_id,
                    address: mac_address.clone(),
                    is_self: is_self,
                    created: netgrasp_event.timestamp,
                    updated: netgrasp_event.timestamp,
                };
                diesel::insert_into(mac::table)
                    .values(&new_mac)
                    .execute(&self.sql)
                    .expect("Error adding mac");

                // Recursively determine the mac_id of the mac address we just added.
                netgrasp_event = self.load_mac_id(netgrasp_event, mac_address.clone(), is_self);
                netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::MacFirstSeen, &mac_address);
                netgrasp_event
            }
        }
    }

    // Retreives ip_id of ip address, adding if not already seen.
    pub fn load_ip_id(&self, mut netgrasp_event: NetgraspEvent, ip_address: String) -> NetgraspEvent {
        //use crate::db::schema::ip;
        use crate::db::schema::ip::dsl::*;
        use crate::db::schema::arp::dsl::{created, arp, src_ip};

        debug_assert!(ip_address != "0.0.0.0");
        netgrasp_event.ip_address = ip_address;

        // @TODO: Update if host_name changes. Perform fewer lookups, instead use value from table most of the time.
        let ip_addr: std::net::IpAddr = match netgrasp_event.ip_address.parse() {
            Ok(i) => i,
            Err(e) => {
                error!("Error parsing ip_address {}: [{}]", &netgrasp_event.ip_address, e);
                // @TODO: how should we handle this?
                return netgrasp_event;
            },
        };
        netgrasp_event.host_name = match lookup_addr(&ip_addr) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to look up host_name for ip_address {}: [{}]", &netgrasp_event.ip_address, e);
                "unknown".to_string()
            },
        };

        let load_ip_id;
        // If the IP address doesn't have an associated mac_id, see if we can query it from our database.
        if netgrasp_event.mac_id == 0 {
            // @TODO: if ip.address == ip.host_name, perhaps perform another reverse IP lookup.
            // @TODO: further, perhaps always perform a new reverse IP lookup every ~24 hours? Or,
            // simply respect the DNS ttl?
            let load_ip_id_query = ip 
                .filter(address.eq(&netgrasp_event.ip_address));
            debug!("load_ip_id: {}", debug_query::<Sqlite, _>(&load_ip_id_query).to_string());
            load_ip_id = load_ip_id_query
                .get_result::<Ip>(&self.sql);
        }
        // While this IP address does have an associated mac_id, it may not yet be in our database (mac_id = 0).
        else {
            let load_ip_id_query = sql_query("SELECT * FROM ip WHERE address = ? AND (mac_id = ? OR mac_id = 0)")
                .bind::<Text, _>(&netgrasp_event.ip_address)
                .bind::<Integer, _>(netgrasp_event.mac_id);
            debug!("load_ip_id: {}", debug_query::<Sqlite, _>(&load_ip_id_query).to_string());
            load_ip_id = load_ip_id_query
                .get_result::<Ip>(&self.sql);
        }

        match load_ip_id {
            // We have seen this IP before, return the ip_id.
            Ok(i) => {
                netgrasp_event.host_name = i.host_name;
                netgrasp_event.custom_name = i.custom_name;
                // While we've seen the IP before, we may not have seen the associated MAC address.
                if netgrasp_event.mac_id != 0 {
                    // We're seeing the MAC associated with this IP for the first time, update it.
                    if i.mac_id == 0 {
                        let update_ip_query = diesel::update(ip)
                            .filter(address.eq(&netgrasp_event.ip_address))
                            .set((mac_id.eq(&netgrasp_event.mac_id), updated.eq(&netgrasp_event.timestamp)));
                            debug!("load_ip_id: update_ip_query {}", debug_query::<Sqlite, _>(&update_ip_query).to_string());
                            match update_ip_query.execute(&self.sql) {
                                Err(e) => {
                                    error!("Error inserting into ip table: [{}]", e);
                                    // We have to exit or we'll get into an infinite loop.
                                    std::process::exit(1);
                                }
                                Ok(_) => (),
                            }
                        netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpFirstSeen, &i.address);
                        // Devices are currently tied to IPs
                        let device_name = get_device_name(&netgrasp_event);
                        netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::DeviceFirstSeen, &device_name);
                    }
                    else {
                        // Determine the last time the IP was seen recently.
                        let previously_seen_query = arp
                            .select(created)
                            .filter(src_ip.eq(&netgrasp_event.ip_address))
                            .order(created.desc())
                            .limit(2);
                            debug!("load_ip_id: previously_seen_query {}", debug_query::<Sqlite, _>(&previously_seen_query).to_string());
                        let now = time::timestamp_now();
                        let inactive_before: i32 = (now - IPS_ACTIVE_FOR) as i32;
                        let previously_seen: i32 = match previously_seen_query.get_result(&self.sql) {
                            Ok(p) => p,
                            Err(_) => now as i32,
                        };
                        if previously_seen < inactive_before {
                            let ip_address = netgrasp_event.ip_address.to_string();
                            netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpReturned, &ip_address);
                            // Devices are currently tied to IPs
                            let device_name = get_device_name(&netgrasp_event);
                            netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::DeviceReturned, &device_name);
                        }
                    }
                }
                // Return the ip_id.
                netgrasp_event.ip_id = i.ip_id;
                let ip_address = netgrasp_event.ip_address.to_string();
                if netgrasp_event.mac_id == 0 {
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpRequest, &ip_address);
                }
                else {
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpSeen, &ip_address);
                    let device_name = get_device_name(&netgrasp_event);
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::DeviceSeen, &device_name);
                }
            }
            // We're seeing this IP for the first time, add it to the database.
            Err(_) => {
                // If this mac address doesn't exist, add it.
                info!("detected new hostname({}) with (ip address, mac_id) pair: ({}, {})", &netgrasp_event.host_name, &netgrasp_event.ip_address, netgrasp_event.mac_id);

                let new_ip = NewIp {
                    mac_id: netgrasp_event.mac_id,
                    address: netgrasp_event.ip_address.to_string(),
                    host_name: netgrasp_event.host_name.to_string(),
                    custom_name: netgrasp_event.custom_name.to_string(),
                    created: netgrasp_event.timestamp,
                    updated: netgrasp_event.timestamp,
                };

                let insert_ip_query = diesel::insert_into(ip)
                    .values(&new_ip);
                debug!("load_ip_id: insert_ip_query {}", debug_query::<Sqlite, _>(&insert_ip_query).to_string());
                match insert_ip_query.execute(&self.sql) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Error inserting ip into database: [{}]", e);
                        // We have to exit or we'll get into an infinite loop.
                        std::process::exit(1);
                    }
                }

                // Recursively determine the ip_id of the IP address we just added.
                let ip_address = netgrasp_event.ip_address.to_string();
                netgrasp_event = self.load_ip_id(netgrasp_event, ip_address.to_string());
                if netgrasp_event.mac_id == 0 {
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpFirstRequest, &ip_address);
                }
                else {
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpFirstSeen, &ip_address);
                    // Devices are currently tied to IPs
                    let device_name = get_device_name(&netgrasp_event);
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::DeviceFirstSeen, &device_name);
                }
            }
        }
        netgrasp_event
    }

    pub fn process_inactive_ips(&self) {
        use crate::db::schema::arp::dsl::*;
        use diesel::*;

        let now = time::timestamp_now();
        let inactive_before: i32 = (now - IPS_ACTIVE_FOR) as i32;
        // 1) Set is_active to 0 where created < active_seconds ago
        let update_arp_query = diesel::update(arp)
            .filter(created.le(inactive_before))
            .set((is_active.eq(0), updated.eq(now as i32)));
        debug!("process_inactive_ips: update_arp_query: {}", debug_query::<Sqlite, _>(&update_arp_query).to_string());
        match update_arp_query.execute(&self.sql) {
            Err(e) => error!("Unexpected error marking arps inactive: {}", e),
            Ok(_) => (),
        }

        // 2a) identify expired ip adresses
        let inactive_ip_ids_query = sql_query("SELECT src_ip_id FROM arp WHERE src_ip != '0.0.0.0' GROUP BY src_ip_id HAVING MAX(created) < ?")
            .bind::<Integer, _>(inactive_before);
        debug!("process_inactive_ips: inactive_ip_ids_query: {}", debug_query::<Sqlite, _>(&inactive_ip_ids_query).to_string());
        let inactive_ip_ids: Vec<DistinctIpId> = match inactive_ip_ids_query.load::<DistinctIpId>(&self.sql) {
            Ok(i) => i,
            Err(e) => {
                error!("process_inactive_ips: unexpected error loading inactive ip ids: {}", e);
                // This shouldn't happen, exit.
                std::process::exit(1);
            }
        };

        // 2b) send notifications for these ips: they've gone inactive
        for inactive_ip_id in inactive_ip_ids {
            let inactive_ip_query = arp
                .select((updated, interface, src_mac_id, src_mac, is_self, src_ip_id, src_ip, event_type, event_description, host_name, custom_name, src_vendor_id, vendor_name, vendor_full_name))
                .filter(src_ip_id.eq(inactive_ip_id.src_ip_id))
                .filter(processed.eq(0))
                .filter(is_active.eq(0))
                .limit(1);
            debug!("process_inactive_ips: inactive_ip_query: {}", debug_query::<Sqlite, _>(&inactive_ip_query).to_string());
            match inactive_ip_query.get_result(&self.sql) {
                Ok(i) => {
                    let mut netgrasp_event: NetgraspEvent = i;
                    let ip_address = netgrasp_event.ip_address.to_string();
                    netgrasp_event = self.send_notification(netgrasp_event, NetgraspEventType::IpInactive, &ip_address);
                    let device_name = get_device_name(&netgrasp_event);
                    self.send_notification(netgrasp_event, NetgraspEventType::DeviceInactive, &device_name);
                }
                Err(e) => {
                    debug!("process_inactive_ips: failed to load inactive ip event details: {}", e);
                }
            }
        }

        // 3) Set processed = 1 for all is_active = 0 AND processed = 0
        let response = diesel::update(arp)
            .filter(processed.eq(0))
            .filter(is_active.eq(0))
            .set((processed.eq(1), updated.eq(now as i32)))
            .execute(&self.sql);
        match response {
            Err(e) => eprintln!("unexpected error processing inactive ips: {}", e),
            Ok(_) => (),
        }
    }

    pub fn detect_netscan(&self, scan_range: u64) -> bool {
        use crate::db::schema::arp::dsl::*;
        use crate::db::schema::ip;

        let mut detected_netscan = false;
        let load_netscan_query = sql_query("SELECT COUNT(DISTINCT tgt_ip_id) AS tgt_ip_id_count, src_ip_id FROM arp WHERE created > ? GROUP BY src_ip_id HAVING tgt_ip_id_count > ?")
            .bind::<Integer, _>(time::elapsed(scan_range) as i32)
            // @TODO: expose as configuration how many devices talked to constitutes a netscan
            .bind::<Integer, _>(50);
        debug!("detect_netscan: load_netscan_query: {}", debug_query::<Sqlite, _>(&load_netscan_query).to_string());
        match load_netscan_query.get_results::<NetworkScan>(&self.sql) {
            Ok(netscans) => {
                if netscans.len() > 0 {
                    info!("detect_netscan: {} netscans", netscans.len());
                }
                for netscan in netscans {
                    let netscan_event_query = arp
                        .inner_join(ip::table)
                        .select((updated, interface, src_mac_id, src_mac, is_self, src_ip_id, src_ip, event_type, event_description, ip::host_name, ip::custom_name, src_vendor_id, vendor_name, vendor_full_name))
                        .filter(src_ip_id.eq(netscan.src_ip_id))
                        .limit(1);
                    debug!("detect_netscan: netscan_event_query: {}", debug_query::<Sqlite, _>(&netscan_event_query).to_string());
                    match netscan_event_query.get_result(&self.sql) {
                        Ok(i) => {
                            let netgrasp_event: NetgraspEvent = i;
                            info!("detect_netscan: netscan of {}+ devices by {} ({}) [{}]", netscan.tgt_ip_id_count, &get_device_name(&netgrasp_event), &netgrasp_event.ip_address, &netgrasp_event.mac_address);
                            let device_name = get_device_name(&netgrasp_event);
                            self.send_notification(netgrasp_event, NetgraspEventType::NetworkScan, &device_name);
                            detected_netscan = true;
                        }
                        Err(e) => {
                            info!("detect_netscan: failed to load netscan event details: {}", e);
                        }
                    }
                }
            },
            Err(e) => {
                debug!("detect_netscan: load_netscan_query: error: {}", e);
                return detected_netscan
            }
        }
        detected_netscan
    }

    fn send_notification(&self, mut netgrasp_event: NetgraspEvent, netgrasp_event_type: NetgraspEventType, device: &str) -> NetgraspEvent {
        use crate::db::schema::arp::dsl::*;
        use std::convert::TryInto;

        let event_detail = netgrasp_event_detail(netgrasp_event_type);
        netgrasp_event.event_type = event_detail.name.to_string();
        netgrasp_event.event_description = event_detail.description.to_string();
        debug!("send_notification: priority: {}, name: {}, description: {}, netgrasp_event: {:?}", &event_detail.priority, &event_detail.name, &event_detail.description, &netgrasp_event);

        // @TODO: Expose this to configuration:
        if event_detail.priority > 140 {
            // Determine how many times the IP was seen recently.
            let now = time::timestamp_now();
            let inactive_before: i32 = (now - IPS_ACTIVE_FOR) as i32;
            let recently_seen_count = diesel::dsl::sql::<diesel::sql_types::BigInt>("COUNT(src_ip)");
            let recently_seen_query = arp
                .select(recently_seen_count)
                .filter(src_ip.eq(&netgrasp_event.ip_address))
                .filter(created.ge(inactive_before));
            debug!("send_notification: recently_seen_query: {}", debug_query::<Sqlite, _>(&recently_seen_query).to_string());
            let recently_seen: i64 = match recently_seen_query.load(&self.sql) {
                Ok(r) => *r.first().unwrap(),
                Err(_) => 0,
            };
            let recently_seen_string: String;
            if recently_seen == 1 {
                recently_seen_string = "1 time".to_string();
            }
            else if recently_seen == 0 {
                recently_seen_string = "never".to_string();
            }
            else {
                recently_seen_string = format!("{} times", recently_seen);
            }

            // Determine the last time the IP was seen recently.
            let previously_seen_query = arp
                .select(created)
                .filter(src_ip.eq(&netgrasp_event.ip_address))
                .order(created.desc())
                .limit(2);
            debug!("send_notification: previously_seen_query: {}", debug_query::<Sqlite, _>(&previously_seen_query).to_string());
            // convert i32 timestamp from SQLite into u64 for helpers
            let previously_seen_string: String = match previously_seen_query.load(&self.sql) {
                Ok(l) => {
                    let timestamp_string: String = match l.last() {
                        Some(t) => {
                            let g: i32 = *t;
                            let timestamp: u64 = g.try_into().expect("failed to convert i32 to u64");
                            format::time_ago(timestamp, true)
                        },
                        None => "never".to_string(),
                    };
                    timestamp_string
                },
                Err(_) => "never".to_string(),
            };

            // Determine the first time the IP was seen.
            let min_created = diesel::dsl::sql::<diesel::sql_types::Integer>("MIN(created)");
            let first_seen_query = arp
                .select(min_created)
                .filter(src_ip.eq(&netgrasp_event.ip_address));
            debug!("send_notification: first_seen_query: {}", debug_query::<Sqlite, _>(&first_seen_query).to_string());
            // convert i32 timestamp from SQLite into u64 for helpers
            let first_seen: u64 = match first_seen_query.load(&self.sql) {
                Ok(l) => {
                    let timestamp: i32 = *l.first().unwrap();
                    timestamp.try_into().expect("failed to convert i32 to u64")
                }
                Err(_) => time::timestamp_now(),
            };

            // Build list of devices that have been pinged.
            let current_device = TalkedTo {
                ip_address: netgrasp_event.ip_address.to_string(),
                mac_address: netgrasp_event.mac_address.to_string(),
            };
            let devices_talked_to_query = arp
                .select((tgt_ip, tgt_mac))
                .filter(src_ip.eq(&netgrasp_event.ip_address))
                .filter(created.ge(time::elapsed(86400) as i32))
                .group_by(tgt_ip)
                .limit(TALKED_TO_LIMIT);
            debug!("send_notification: devices_talked_to_query: {}", debug_query::<Sqlite, _>(&devices_talked_to_query).to_string());
            let mut self_included: i32 = 1;
            let devices_talked_to: Vec<TalkedTo> = match devices_talked_to_query.load(&self.sql) {
                Ok(mut talked_to) => {
                    // The current ARP packet isn't in the database, be sure the device is included
                    if !talked_to.contains(&current_device) {
                        talked_to.push(current_device);
                        self_included = 0;
                    }
                    talked_to
                },
                Err(_) => {
                    self_included = 0;
                    vec!(current_device)
                }
            };
            let devices_talked_to_count_query = sql_query("SELECT COUNT(DISTINCT tgt_ip_id) AS counter FROM arp WHERE src_ip_id = ? AND created > ?")
                .bind::<Integer, _>(netgrasp_event.ip_id as i32)
                .bind::<Integer, _>(time::elapsed(86400) as i32);
            debug!("send_notification: devices_talked_to_count_query: {}", debug_query::<Sqlite, _>(&devices_talked_to_count_query).to_string());
            let devices_talked_to_count = match devices_talked_to_count_query.get_result(&self.sql) {
                Ok(c) => {
                    let talked_to_count: TalkedToCount = c;
                    TalkedToCount {
                        counter: talked_to_count.counter + self_included,
                    }
                }
                Err(e) => {
                    debug!("devices_talked_to_count_query error: {}", e);
                    TalkedToCount {
                        counter: 1,
                    }
                }
            };
            let device_string: String;
            if devices_talked_to_count.counter == 1 {
                device_string = "device".to_string();
            }
            else {
                device_string = "devices".to_string();
            }

            let mut notification = Notification::init("Netgrasp", "", &event_detail.description);
            notification.add_value("event".to_string(), event_detail.name);
            notification.add_value("device".to_string(), device.to_string());
            if netgrasp_event.ip_address != "" {
                notification.add_value("ip".to_string(), netgrasp_event.ip_address.clone());
            }
            else {
                notification.add_value("ip".to_string(), "(unknown)".to_string());
            }
            if netgrasp_event.mac_address != "" {
                notification.add_value("mac".to_string(), netgrasp_event.mac_address.clone());
            }
            else {
                notification.add_value("mac".to_string(), "unknown".to_string());
            }
            let device_name = get_device_name(&netgrasp_event);
            notification.add_value("name".to_string(), device_name);
            notification.add_value("host_name".to_string(), netgrasp_event.host_name.clone());
            notification.add_value("vendor_name".to_string(), netgrasp_event.vendor_name.clone());
            notification.add_value("vendor_full_name".to_string(), netgrasp_event.vendor_full_name.clone());
            let wrapped_vendor: String;
            let device_name = get_device_name(&netgrasp_event);
            if netgrasp_event.vendor_full_name == "unknown" {
                wrapped_vendor = "".to_string();
            }
            else if netgrasp_event.vendor_full_name == device_name {
                wrapped_vendor = "".to_string();
            }
            else {
                wrapped_vendor = format!("({})", netgrasp_event.vendor_full_name.clone());
            }
            notification.add_value("wrapped_vendor".to_string(), wrapped_vendor);
            notification.add_value("detail".to_string(), event_detail.description);
            notification.add_value("interface".to_string(), netgrasp_event.interface.clone());
            notification.add_value("first_seen".to_string(), format::time_ago(first_seen, true));
            notification.add_value("previously_seen".to_string(), previously_seen_string);
            notification.add_value("recently_seen".to_string(), recently_seen_string);
            notification.add_value("devices_talked_to_count".to_string(), devices_talked_to_count.counter.to_string());
            notification.add_value("device_string".to_string(), device_string);
            notification.set_title_template(templates::NETGRASP_TITLE_TEMPLATE.to_string());
            notification.set_short_text_template(templates::NETGRASP_TEXT_TEMPLATE.to_string());
            notification.set_short_html_template(templates::NETGRASP_HTML_TEMPLATE.to_string());
            notification.set_long_text_template(templates::NETGRASP_TEXT_TEMPLATE.to_string());
            notification.set_long_html_template(templates::NETGRASP_HTML_TEMPLATE.to_string());
            match notification.send("http://localhost:8000", event_detail.priority, 0, None) {
                Err(e) => eprintln!("Error sending notification: {:?}", e),
                Ok(_) => (),
            };
        }
        netgrasp_event
    }
}

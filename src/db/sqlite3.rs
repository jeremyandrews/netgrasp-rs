use diesel::prelude::*;
use diesel::sql_types::{Text, Integer};
use diesel::sql_query;
use diesel_migrations::{run_pending_migrations, RunMigrationsError};
use dns_lookup::{lookup_addr};
use eui48::MacAddress;
use oui::OuiDatabase;
use crate::db::models::*;
use crate::utils::time;
use rqpush::Notification;
use crate::notifications::templates;
use smoltcp::wire::ArpOperation;

pub struct NetgraspDb {
    sql: SqliteConnection,
    oui: OuiDatabase,
}

#[derive(Debug)]
pub struct NetgraspEvent {
    timestamp: i32,
    interface: String,
    mac_id: i32,
    ip_id: i32,
    host_name: String,
    vendor_id: i32,
    vendor_name: String,
    vendor_full_name: String,
}

#[derive(Debug, Queryable)]
pub struct NetgraspActiveDevice {
    pub interface: String,
    pub ip_address: String,
    pub mac_address: String,
    pub host_name: String,
    pub vendor_name: String,
    pub vendor_full_name: String,
    pub recently_seen_count: i64,
    pub recently_seen_first: i32,
    pub recently_seen_last: i32,
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
            timestamp: time::timestamp_now() as i32,
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
            //sql: SqliteConnection::establish(&sql_database_path).unwrap_or_else(|_| panic!("Error connecting to {}", sql_database_path)),
            sql: SqliteConnection::establish(&sql_database_path).unwrap(),
            oui: OuiDatabase::new_from_file(oui_database_path.as_str()).unwrap(),
        }
    }

    pub fn migrate(&self) -> std::result::Result<(), RunMigrationsError> {
        run_pending_migrations(&self.sql)
    }

    // Returns a vector of all currently known active devices.
    pub fn get_active_devices(&self) -> Vec<NetgraspActiveDevice> {
        use crate::db::schema::arp::dsl::*;

        let min_updated = diesel::dsl::sql::<diesel::sql_types::Integer>("MIN(updated)");
        let max_updated = diesel::dsl::sql::<diesel::sql_types::Integer>("MAX(updated)");
        let count_src_ip = diesel::dsl::sql::<diesel::sql_types::BigInt>("COUNT(src_ip)");
        let active_devices: Vec<(NetgraspActiveDevice)> = arp
            .select((interface, src_ip, src_mac, host_name, vendor_name, vendor_full_name, &count_src_ip, min_updated, &max_updated))
            .filter(src_ip.ne("0.0.0.0"))
            .group_by(src_ip)
            .order((max_updated.clone().desc(), count_src_ip.clone().desc()))
            .load(&self.sql)
            .expect("Error loading arp");
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
                trace!("ARP request");
                // A MAC broadcast isn't a real MAC address, so don't store it.
                if arp_packet.src_is_broadcast {
                    debug!("ignoring arp broadcast source of {} [{}]", arp_packet.src_ip, arp_packet.src_mac)
                }
                // Log all non-broadcast mac addresses.
                else {
                    netgrasp_event_src = self.load_mac_id(netgrasp_event_src, arp_packet.src_mac.to_string(), arp_packet.src_is_self as i32);
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
                    netgrasp_event_src = self.load_mac_id(netgrasp_event_src, arp_packet.src_mac.to_string(), arp_packet.src_is_self as i32);
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

        let new_arp = NewArp {
            src_mac_id: netgrasp_event_src.mac_id,
            src_ip_id: netgrasp_event_src.ip_id,
            tgt_ip_id: netgrasp_event_tgt.ip_id,
            interface: arp_packet.interface,
            host_name: netgrasp_event_src.host_name,
            custom_name: "".to_string(),
            vendor_name: netgrasp_event_src.vendor_name,
            vendor_full_name: netgrasp_event_src.vendor_full_name,
            src_mac: arp_packet.src_mac.to_string(),
            src_ip: arp_packet.src_ip.to_string(),
            tgt_mac: arp_packet.tgt_mac.to_string(),
            tgt_ip: arp_packet.tgt_ip.to_string(),
            operation: operation,
            matched: 0,
            created: netgrasp_event_src.timestamp,
            updated: netgrasp_event_src.timestamp
        };

        diesel::insert_into(arp::table)
            .values(&new_arp)
            .execute(&self.sql)
            .expect("Error logging arp");
    }

    pub fn log_event(&self, netgrasp_event: &NetgraspEvent, event_type: &str) {
        use crate::db::schema::event;

        let new_event = NewEvent {
            mac_id: netgrasp_event.mac_id,
            ip_id: netgrasp_event.ip_id,
            vendor_id: netgrasp_event.vendor_id,
            interface: netgrasp_event.interface.clone(),
            // @TODO: network
            network: "".to_string(),
            description: event_type.to_string(),
            // @TODO: processed (what is this?)
            processed: 0,
            created: netgrasp_event.timestamp,
            updated: netgrasp_event.timestamp
        };
        diesel::insert_into(event::table)
            .values(&new_event)
            .execute(&self.sql)
            .expect("Error logging event");
    }

    pub fn send_notification(&self, event: &str, device: &str, detail: &str) {
        let mut notification = Notification::init("Netgrasp", "[netgrasp] {{event}}: {{device}}", "A device returned to your network");
        notification.add_value("event".to_string(), event.to_string());
        notification.add_value("device".to_string(), device.to_string());
        notification.add_value("ip".to_string(), device.to_string());
        notification.add_value("name".to_string(), device.to_string());
        notification.add_value("detail".to_string(), detail.to_string());
        notification.set_short_text_template(templates::NETGRASP_TEXT_TEMPLATE.to_string());
        notification.set_short_html_template(templates::NETGRASP_HTML_TEMPLATE.to_string());
        notification.set_long_text_template(templates::NETGRASP_TEXT_TEMPLATE.to_string());
        notification.set_long_html_template(templates::NETGRASP_HTML_TEMPLATE.to_string());
        notification.send("http://localhost:8000", 50, 0, None);
    }

    fn load_vendor_id(&self, mut netgrasp_event: NetgraspEvent) -> NetgraspEvent {
        use crate::db::schema::vendor;

        trace!("SELECT vendor_id FROM vendor WHERE name = '{}' AND full_name = '{}';", &netgrasp_event.vendor_name, &netgrasp_event.vendor_full_name);

        let results = vendor::table
            .filter(vendor::name.eq(&netgrasp_event.vendor_name))
            .filter(vendor::full_name.eq(&netgrasp_event.vendor_full_name))
            .load::<Vendor>(&self.sql)
            .expect("Error loading vendor");
        
        if results.len() == 1 {
            // Return the vendor_id.
            netgrasp_event.vendor_id = results[0].vendor_id;
            self.log_event(&netgrasp_event, EVENT_VENDOR_SEEN);
            netgrasp_event
        }
        // If this mac address doesn't exist, add it.
        else {
            // @TODO: trigger new_vendor event.
            info!("detected new vendor({} [{}])", &netgrasp_event.vendor_full_name, &netgrasp_event.vendor_name);

            let new_vendor = NewVendor {
                name: netgrasp_event.vendor_name.clone(),
                full_name: netgrasp_event.vendor_full_name.clone(),
                created: netgrasp_event.timestamp,
                updated: netgrasp_event.timestamp,
            };
            diesel::insert_into(vendor::table)
                .values(&new_vendor)
                .execute(&self.sql)
                .expect("Error adding vendor");

            // Recursively determine the vendor_id we just added.
            // @TODO: can we get that from our earlier insert?
            netgrasp_event = self.load_vendor_id(netgrasp_event);
            self.log_event(&netgrasp_event, EVENT_VENDOR_SEEN_FIRST);
            netgrasp_event
        }
    }

    // Retreives mac_id of mac address, adding if not already seen.
    fn load_mac_id(&self, mut netgrasp_event: NetgraspEvent, mac_address: String, is_self: i32) -> NetgraspEvent {
        use crate::db::schema::mac;

        trace!("SELECT mac_id, is_self FROM mac WHERE address = '{}';", &mac_address);
        let results = mac::table
            .filter(mac::address.eq(&mac_address))
            .load::<Mac>(&self.sql)
            .expect("Error loading mac");

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

        if results.len() == 1 {
            // Return the mac_id.
            let existing_is_self = results[0].is_self;
            debug_assert!(existing_is_self == is_self);
            netgrasp_event.mac_id = results[0].mac_id;
            self.log_event(&netgrasp_event, EVENT_MAC_SEEN);
            netgrasp_event
        }
        // If this mac address doesn't exist, add it.
        else {
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
            netgrasp_event = self.load_mac_id(netgrasp_event, mac_address, is_self);
            self.log_event(&netgrasp_event, EVENT_MAC_SEEN_FIRST);
            netgrasp_event
        }
    }

    // Retreives ip_id of ip address, adding if not already seen.
    pub fn load_ip_id(&self, mut netgrasp_event: NetgraspEvent, ip_address: String) -> NetgraspEvent {
        //use crate::db::schema::ip;
        use crate::db::schema::ip::dsl::*;

        debug_assert!(ip_address != "0.0.0.0");

        let results;
        // If the IP address doesn't have an associated mac_id, see if we can query it from our database.
        if netgrasp_event.mac_id == 0 {
            trace!("SELECT ip_id, mac_id FROM ip WHERE address = '{}';", &ip_address);
            // @TODO: if ip.address == ip.host_name, perhaps perform another reverse IP lookup.
            // @TODO: further, perhaps always perform a new reverse IP lookup every ~24 hours? Or,
            // simply respect the DNS ttl?
            results = ip
                .filter(address.eq(ip_address.clone()))
                .load::<Ip>(&self.sql)
                .expect("Error loading ip");
        }
        // While this IP address does have an associated mac_id, it may not yet be in our database (mac_id = 0).
        else {
            trace!("SELECT ip_id, mac_id FROM ip WHERE address = '{}' AND (mac_id = {} OR mac_id = 0);", &ip_address, netgrasp_event.mac_id);
            results = sql_query("SELECT * FROM ip WHERE address = ? AND (mac_id = ? OR mac_id = 0)")
                .bind::<Text, _>(ip_address.clone())
                .bind::<Integer, _>(netgrasp_event.mac_id)
                .load::<Ip>(&self.sql)
                .expect("Error loading ip");
        }

        // @TODO: Update if host_name changes. Perform fewer lookups, instead use value from table most of the time.
        let ip_addr: std::net::IpAddr = ip_address.parse().unwrap();
        netgrasp_event.host_name = lookup_addr(&ip_addr).unwrap();

        // We have seen this IP before, return the ip_id.
        if results.len() == 1 {
            // While we've seen the IP before, we may not have seen the associated MAC address.
            if netgrasp_event.mac_id != 0 {
                let existing_mac_id = results[0].mac_id;
                // We're seeing the MAC associated with this IP for the first time, update it.
                if existing_mac_id == 0 {
                    info!("UPDATE ip SET mac_id = {}, updated = {} WHERE address = '{}';",
                        netgrasp_event.mac_id, netgrasp_event.timestamp, &ip_address);
                    
                    diesel::update(ip)
                        .filter(address.eq(&ip_address))
                        .set((mac_id.eq(&netgrasp_event.mac_id), updated.eq(&netgrasp_event.timestamp)))
                        .execute(&self.sql);

                    self.log_event(&netgrasp_event, EVENT_IP_SEEN_FIRST);
                }
            }
            // Return the ip_id.
            netgrasp_event.ip_id = results[0].ip_id;
            if netgrasp_event.mac_id == 0 {
                self.log_event(&netgrasp_event, EVENT_IP_REQUEST);
            }
            else {
                self.log_event(&netgrasp_event, EVENT_IP_SEEN);
                self.send_notification("new IP seen", &ip_address, "A new IP has been seen on your network");
            }
        }
        // We're seeing this IP for the first time, add it to the database.
        else {
            info!("detected new hostname({}) with (ip address, mac_id) pair: ({}, {})", &netgrasp_event.host_name, &ip_address, netgrasp_event.mac_id);

            trace!("INSERT INTO ip (address, mac_id, host_name, created, updated) VALUES('{}', {}, '{}', {}, {});",
                &ip_address, netgrasp_event.mac_id, &netgrasp_event.host_name, netgrasp_event.timestamp, netgrasp_event.timestamp);

            let new_ip = NewIp {
                mac_id: netgrasp_event.mac_id,
                address: ip_address.clone(),
                host_name: netgrasp_event.host_name.clone(),
                custom_name: "".to_string(),
                created: netgrasp_event.timestamp,
                updated: netgrasp_event.timestamp,
            };
            diesel::insert_into(ip)
                .values(&new_ip)
                .execute(&self.sql)
                .expect("Error adding ip");

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

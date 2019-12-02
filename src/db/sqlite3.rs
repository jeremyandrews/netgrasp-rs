use crate::db::models::*;
use crate::notifications::templates;
use crate::utils::{format, math, time};
use diesel::prelude::*;
use diesel::sql_types::{Integer, Text};
use diesel::sqlite::Sqlite;
use diesel::{debug_query, sql_query};
use diesel_migrations::{run_pending_migrations, RunMigrationsError};
use dns_lookup::lookup_addr;
use eui48::MacAddress;
use handlebars::to_json;
use oui::OuiDatabase;
use rqpush::Notification;

// Maximum number of devices to list when reporting on network events
const MAX_DEVICES_TO_LIST: i32 = 256;

#[derive(Debug)]
pub enum NetgraspEventWrapperType {
    None,
    Arp,
    //Dhcp,
}

impl Default for NetgraspEventWrapperType {
    fn default() -> NetgraspEventWrapperType {
        NetgraspEventWrapperType::None
    }
}

#[derive(Debug, Default)]
pub struct NetgraspArpEvent {
    mac: Mac,
    vendor: Vendor,
    ip: Ip,
}

// @TODO: Use generics to support non-Arp events (ie, DHCP)
#[derive(Debug, Default)]
pub struct NetgraspEventWrapper {
    events: Vec<NetgraspEventType>,
    mtype: NetgraspEventWrapperType,
    network_event: NewNetworkEvent,
    interface: Interface,
    source: NetgraspArpEvent,
    target: NetgraspArpEvent,
    timestamp: i32,
}

impl NetgraspEventWrapper {
    pub fn initialize(mtype: NetgraspEventWrapperType) -> Self {
        NetgraspEventWrapper {
            events: vec![],
            mtype: mtype,
            network_event: NewNetworkEvent::default(),
            interface: Interface::default(),
            source: NetgraspArpEvent::default(),
            target: NetgraspArpEvent::default(),
            timestamp: time::timestamp_now() as i32,
        }
    }
}

// IPs are considered active for 3 hours
pub const IPS_ACTIVE_FOR: u64 = 10800;

pub struct NetgraspDb {
    sql: SqliteConnection,
    oui: OuiDatabase,
    minimum_priority: u8,
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

#[derive(Debug, Default, PartialEq, Queryable, QueryableByName, Serialize)]
pub struct TalkedTo {
    #[sql_type = "Integer"]
    pub tgt_mac_id: i32,
    #[sql_type = "Integer"]
    pub tgt_ip_id: i32,
    #[sql_type = "Integer"]
    pub count: i32,
}

#[derive(Debug, Default, PartialEq, Queryable, QueryableByName, Serialize)]
pub struct TalkedToCount {
    #[sql_type = "Integer"]
    pub counter: i32,
}

#[derive(Debug, Default, PartialEq, Queryable, QueryableByName, Serialize)]
pub struct Statistics {
    #[sql_type = "Integer"]
    pub count: i32,
}

#[derive(Debug, Default, PartialEq, Queryable, QueryableByName, Serialize)]
pub struct MacDetail {
    #[sql_type = "Text"]
    pub address: String,
    #[sql_type = "Text"]
    pub full_name: String,
}

#[derive(Debug, Default, PartialEq, Queryable, QueryableByName)]
pub struct IpDetail {
    #[sql_type = "Text"]
    pub address: String,
    #[sql_type = "Text"]
    pub host_name: String,
    #[sql_type = "Text"]
    pub custom_name: String,
    #[sql_type = "Integer"]
    pub mac_id: i32,
}

#[derive(Debug, Default, Serialize)]
pub struct TalkedToDisplay {
    pub name: String,
    pub count: i32,
    pub count_string: String,
}

#[derive(Debug, Queryable, QueryableByName)]
pub struct DistinctIpId {
    #[sql_type = "Integer"]
    pub ip_id: i32,
}

#[derive(Debug, Default, Queryable, QueryableByName)]
pub struct NetworkScan {
    #[sql_type = "Integer"]
    pub tgt_ip_id_count: i32,
    #[sql_type = "Integer"]
    pub ip_id: i32,
}

#[derive(Debug, Clone)]
enum NetgraspEventType {
    InterfaceFirstSeen,
    InterfaceSeen,
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
    IpHostnameChanged,
    //IpDuplicate,
    //IpNotOnNetwork,
    DeviceFirstSeen,
    DeviceSeen,
    DeviceInactive,
    DeviceReturned,
    NetworkScan,
}

#[derive(Debug, Default)]
struct NetgraspEventDetail {
    name: String,
    description: String,
    priority: u8,
}

fn netgrasp_event_detail(netgrasp_event_type: &NetgraspEventType) -> NetgraspEventDetail {
    match netgrasp_event_type {
        NetgraspEventType::InterfaceSeen => NetgraspEventDetail {
            name: "interface seen".to_string(),
            description: "Interface active".to_string(),
            priority: 3,
        },
        NetgraspEventType::MacSeen => NetgraspEventDetail {
            name: "mac seen".to_string(),
            description: "Mac address on network".to_string(),
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
        NetgraspEventType::InterfaceFirstSeen => NetgraspEventDetail {
            name: "new interface".to_string(),
            description: "New interface active".to_string(),
            priority: 120,
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
        NetgraspEventType::DeviceInactive => NetgraspEventDetail {
            name: "device inactive".to_string(),
            description: "Device on network has gone inactive".to_string(),
            priority: 130,
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
        */
        NetgraspEventType::IpHostnameChanged => NetgraspEventDetail {
            name: "IP hostname changed".to_string(),
            description: "IP hostname changed".to_string(),
            priority: 145,
        },
        /*
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

fn get_device_name(netgrasp_event_wrapper: &NetgraspEventWrapper, is_source: bool) -> String {
    if is_source {
        format::device_name(format::DeviceName {
            custom_name: netgrasp_event_wrapper.source.ip.custom_name.to_string(),
            host_name: netgrasp_event_wrapper.source.ip.host_name.to_string(),
            ip_address: netgrasp_event_wrapper.source.ip.address.to_string(),
            vendor_full_name: netgrasp_event_wrapper.source.vendor.full_name.to_string(),
        })
    } else {
        format::device_name(format::DeviceName {
            custom_name: netgrasp_event_wrapper.target.ip.custom_name.to_string(),
            host_name: netgrasp_event_wrapper.target.ip.host_name.to_string(),
            ip_address: netgrasp_event_wrapper.target.ip.address.to_string(),
            vendor_full_name: netgrasp_event_wrapper.target.vendor.full_name.to_string(),
        })
    }
}

fn name_or_unknown(name: &str) -> String {
    if name == "" {
        return "(unknown)".to_string();
    } else {
        name.to_string()
    }
}

impl NetgraspDb {
    pub fn new(sql_database_path: String, oui_database_path: String, minimum_priority: u8) -> Self {
        NetgraspDb {
            sql: NetgraspDb::establish_sqlite_connection(&sql_database_path),
            oui: NetgraspDb::establish_oui_connection(&oui_database_path),
            minimum_priority: minimum_priority,
        }
    }

    fn establish_sqlite_connection(sqlite_database_path: &str) -> SqliteConnection {
        info!(
            "establishing connection to SQLite database: [{}]",
            sqlite_database_path
        );
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
        info!(
            "establishing connection to OUI database: [{}]",
            oui_database_path
        );
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

    /// Processes a network event
    /// @TODO packet should be a generic to support other than just arp packets
    pub fn record_network_event(&self, packet: crate::net::arp::NetgraspArpPacket) {
        use crate::db::schema::network_event;

        trace!("record_network_event: packet({:?})", &packet);
        // @TODO use a generic
        let mut netgrasp_event_wrapper =
            NetgraspEventWrapper::initialize(NetgraspEventWrapperType::Arp);

        netgrasp_event_wrapper = self.process_arp_packet(netgrasp_event_wrapper, packet);

        netgrasp_event_wrapper.network_event.recent = 1;
        netgrasp_event_wrapper.network_event.processed = 0;
        netgrasp_event_wrapper.network_event.interface_id =
            netgrasp_event_wrapper.interface.interface_id;
        netgrasp_event_wrapper.network_event.mac_id = netgrasp_event_wrapper.source.mac.mac_id;
        netgrasp_event_wrapper.network_event.vendor_id =
            netgrasp_event_wrapper.source.vendor.vendor_id;
        netgrasp_event_wrapper.network_event.ip_id = netgrasp_event_wrapper.source.ip.ip_id;
        netgrasp_event_wrapper.network_event.tgt_mac_id = netgrasp_event_wrapper.target.mac.mac_id;
        netgrasp_event_wrapper.network_event.tgt_vendor_id =
            netgrasp_event_wrapper.target.vendor.vendor_id;
        netgrasp_event_wrapper.network_event.tgt_ip_id = netgrasp_event_wrapper.target.ip.ip_id;
        netgrasp_event_wrapper.network_event.created = netgrasp_event_wrapper.timestamp;
        netgrasp_event_wrapper.network_event.updated = netgrasp_event_wrapper.timestamp;
        debug!("netgrasp_event_wrapper: {:?}", netgrasp_event_wrapper);

        let network_event_insert_query =
            diesel::insert_into(network_event::table).values(&netgrasp_event_wrapper.network_event);
        debug!(
            "record_network_event: network_event_insert_query {}",
            debug_query::<Sqlite, _>(&network_event_insert_query).to_string()
        );
        network_event_insert_query
            .execute(&self.sql)
            .expect("Error recording network event");

        // finally, process events
        for event in &netgrasp_event_wrapper.events {
            self.process_event(event, &netgrasp_event_wrapper);
        }

        self.process_statistics(&netgrasp_event_wrapper);
    }

    fn process_statistics(&self, netgrasp_event_wrapper: &NetgraspEventWrapper) {
        trace!("process_statistics: netgrasp_event_wrapper({:?})", netgrasp_event_wrapper);
        use chrono::prelude::*;
        use crate::db::schema::stats;
        use crate::db::schema::network_event;

        // trends to watch
        // 1) how many times the device was seen over a period of time
        // 2) how many unique devices the device pinged over a period of time
        // 3) average time between network sightings during a period of time
        //
        // periods
        // 1) average for the past hour
        // 2) every ten minutes for the past hour
        // 3) average for the past 24 hours
        // 4) every hour for the past 24 hours
        //
        // goals
        // 1) detect anomalies 
        // 2) passively determine more quickly and less arbitrarily when a device has gone offline

        if netgrasp_event_wrapper.source.mac.mac_id != 0 && netgrasp_event_wrapper.source.ip.ip_id != 0 {
            let utc_now = Utc::now();
            // periods are defined in seconds
            let periods: [i32; 3] = [600, 3600, 86400];
            for period in periods.iter() {
                // for convenience dereference current period as i64
                let period_i64 = *period as i64;

                // the period we're processing ends today, so find the timestamp for the start of today
                let today_start = NaiveDate::from_ymd(utc_now.year(), utc_now.month(), utc_now.day()).and_hms(0, 0, 0);
                // calculate the period we're currently in
                let period_number_end = (utc_now.timestamp() - today_start.timestamp()) / period_i64;
                // get the timestamp of when the period we're currently in started, this is our range end
                let period_end_timestamp = today_start.timestamp() + (period_i64 * period_number_end);
                // get the timestamp of when the previous period started, this is our range start
                let period_start_timestamp = period_end_timestamp - period_i64;
                let period_start = NaiveDateTime::from_timestamp(period_start_timestamp, 0);

                // we may be dealing with yesterday, so re-calculate with period_start
                let period_day_start = NaiveDate::from_ymd(period_start.year(), period_start.month(), period_start.day()).and_hms(0, 0, 0);
                let period_number_start = (period_start_timestamp - period_day_start.timestamp()) / period_i64;
                let yyyymmdd: i32 = period_start.format("%Y%m%d").to_string().parse::<i32>().unwrap();

                debug!("today_start: {}, period_number_start: {}, period_number_end: {}", today_start.timestamp(), period_number_start, period_number_end);

                let total_count =
                    diesel::dsl::sql::<diesel::sql_types::Integer>("total AS count");
                let stats_query = stats::table
                    .select(total_count)
                    .filter(stats::mac_id.eq(netgrasp_event_wrapper.source.mac.mac_id))
                    .filter(stats::ip_id.eq(netgrasp_event_wrapper.source.ip.ip_id))
                    .filter(stats::period_date.eq(yyyymmdd))
                    .filter(stats::period_length.eq(period))
                    .filter(stats::period_number.eq(period_number_start as i32))
                    .limit(1);
                debug!(
                    "process_statistics: stats_query {}",
                    debug_query::<Sqlite, _>(&stats_query).to_string()
                );
                match stats_query.get_result::<i32>(&self.sql)
                {
                    Ok(_) => (),
                    // only calculate new totals if not already done
                    Err(_) => {
                        // how many times the device was seen over time period:
                        let total_over_period_query =
                            sql_query("SELECT COUNT(*) as count FROM network_event WHERE mac_id = ? AND ip_id = ? AND created >= ? AND created < ?")
                                .bind::<Integer, _>(netgrasp_event_wrapper.source.mac.mac_id)
                                .bind::<Integer, _>(netgrasp_event_wrapper.source.ip.ip_id)
                                .bind::<Integer, _>(period_start_timestamp as i32)
                                .bind::<Integer, _>(period_end_timestamp as i32);
                        debug!(
                            "process_statistics: total_over_period_query {}",
                            debug_query::<Sqlite, _>(&total_over_period_query).to_string()
                        );
                        let total_count = match total_over_period_query.get_result::<Statistics>(&self.sql) {
                            Ok(t) => t.count,
                            Err(_) => 0,
                        };
                        debug!("process_statistics: period: {}, total_count: {}", period, total_count);

                        // how many unique devices the device talked to over time period:
                        let unique_over_period_query =
                            sql_query("SELECT COUNT(DISTINCT(tgt_ip_id)) as count FROM network_event WHERE mac_id = ? AND ip_id = ? AND created >= ? AND created < ?")
                                .bind::<Integer, _>(netgrasp_event_wrapper.source.mac.mac_id)
                                .bind::<Integer, _>(netgrasp_event_wrapper.source.ip.ip_id)
                                .bind::<Integer, _>(period_start_timestamp as i32)
                                .bind::<Integer, _>(period_end_timestamp as i32);
                        debug!(
                            "process_statistics: unique_over_period_query 2 {}",
                            debug_query::<Sqlite, _>(&unique_over_period_query).to_string()
                        );
                        let different_count = match unique_over_period_query.get_result::<Statistics>(&self.sql) {
                            Ok(u) => u.count,
                            Err(_) => 0,
                        };
                        debug!("process_statistics: period: {}, different_count: {}", period, different_count);

                        // how many unique devices the device talked to over time period:
                        let load_timestamps_query = network_event::table
                            .select(network_event::created)
                            .filter(network_event::mac_id.eq(&netgrasp_event_wrapper.source.mac.mac_id))
                            .filter(network_event::ip_id.eq(netgrasp_event_wrapper.source.ip.ip_id))
                            .filter(network_event::created.ge(period_start_timestamp as i32))
                            .filter(network_event::created.lt(period_end_timestamp as i32))
                            .order(network_event::created.asc());
                        debug!(
                            "process_statistics: load_timestamps_query {}",
                            debug_query::<Sqlite, _>(&load_timestamps_query).to_string()
                        );
                        let timestamps: Vec<i32> = match load_timestamps_query.get_results(&self.sql)
                        {
                            Ok(t) => t,
                            Err(_) => vec![0]
                        };
                        let mut differences: Vec<i32> = vec![];
                        let mut counter = 1;
                        if timestamps.len() > 1 {
                            let mut value: i32 = timestamps[0];
                            while counter < timestamps.len() {
                                differences.push(timestamps[counter] - value);
                                value = timestamps[counter];
                                counter += 1;
                            }
                        }
                        else {
                            differences.push(0);
                        }

                        let mean = math::mean(&differences);
                        let median = math::median(&differences);

                        debug!("process_statistics: period: {}, different_count: {} mean: {}, meadian: {}", period, different_count, mean, median);

                        let new_stats = NewStats {
                            mac_id: netgrasp_event_wrapper.source.mac.mac_id,
                            ip_id: netgrasp_event_wrapper.source.ip.ip_id,
                            period_date: yyyymmdd,
                            period_length: period_i64 as i32,
                            period_number: period_number_start as i32,
                            total: total_count,
                            different: different_count,
                            mean: mean as f32,
                            median: median as f32,
                            created: netgrasp_event_wrapper.timestamp,
                            updated: netgrasp_event_wrapper.timestamp,
                        };
                        let stats_insert_query =
                            diesel::insert_into(stats::table).values(&new_stats);
                        debug!(
                            "process_stats: stats_insert_query {}",
                            debug_query::<Sqlite, _>(&stats_insert_query).to_string()
                        );
                        stats_insert_query
                            .execute(&self.sql)
                            .expect("Error adding stats");
                    }
                }
            }
        }
    }

    fn process_arp_packet(
        &self,
        mut netgrasp_event_wrapper: NetgraspEventWrapper,
        arp_packet: crate::net::arp::NetgraspArpPacket,
    ) -> NetgraspEventWrapper {
        trace!("process_arp_packet({:?})", arp_packet);

        // Load the interface_id
        netgrasp_event_wrapper = self.process_interface(
            netgrasp_event_wrapper,
            &arp_packet.interface,
            &arp_packet.interface_ip,
        );

        debug!(
            "processing source ip({}) mac({})",
            arp_packet.src_ip, arp_packet.src_mac
        );
        // Process the arp source MAC
        if arp_packet.src_mac.to_string() != "00-00-00-00-00-00"
            && arp_packet.src_mac.to_string() != "ff-ff-ff-ff-ff-ff"
        {
            netgrasp_event_wrapper = self.process_mac(
                netgrasp_event_wrapper,
                &arp_packet.src_mac.to_string(),
                arp_packet.src_is_self as i32,
                true,
            );
        }
        // Process the arp source IP
        if arp_packet.src_ip.to_string() != "0.0.0.0"
            && arp_packet.src_ip.to_string() != "255.255.255.255"
        {
            netgrasp_event_wrapper =
                self.process_ip(netgrasp_event_wrapper, &arp_packet.src_ip.to_string(), true);
        }

        debug!(
            "processing target ip({}) mac({})",
            arp_packet.tgt_ip, arp_packet.tgt_mac
        );
        // Process the arp target MAC
        if arp_packet.tgt_mac.to_string() != "00-00-00-00-00-00"
            && arp_packet.tgt_mac.to_string() != "ff-ff-ff-ff-ff-ff"
        {
            netgrasp_event_wrapper = self.process_mac(
                netgrasp_event_wrapper,
                &arp_packet.tgt_mac.to_string(),
                arp_packet.tgt_is_self as i32,
                false,
            );
        }
        // Process the arp target IP
        if arp_packet.tgt_ip.to_string() != "0.0.0.0"
            && arp_packet.tgt_ip.to_string() != "255.255.255.255"
        {
            netgrasp_event_wrapper = self.process_ip(
                netgrasp_event_wrapper,
                &arp_packet.tgt_ip.to_string(),
                false,
            );
        }

        netgrasp_event_wrapper
    }

    fn process_interface(
        &self,
        mut netgrasp_event_wrapper: NetgraspEventWrapper,
        interface: &str,
        interface_ip: &str,
    ) -> NetgraspEventWrapper {
        trace!("process_interface: {} ({})", interface, interface_ip);
        use crate::db::schema::interface;

        // @TODO: handle new interface and/or new interface_ip

        let interface_query = interface::table
            .filter(interface::label.eq(interface))
            .filter(interface::address.eq(interface_ip));
        debug!(
            "process_interface: {}",
            debug_query::<Sqlite, _>(&interface_query).to_string()
        );
        match interface_query.get_result::<Interface>(&self.sql) {
            // Return interface if exists
            Ok(i) => {
                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::InterfaceSeen);
                netgrasp_event_wrapper.interface = i;
                netgrasp_event_wrapper
            }
            // Otherwise this is the first time we've seen activity on this interface.
            Err(_) => {
                info!("new interface({})", &interface);
                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::InterfaceFirstSeen);

                let new_interface = NewInterface {
                    label: interface.to_string(),
                    // @TODO: (need to confirm aliases show up as different interfaces, or we can't track address)
                    address: interface_ip.to_string(),
                    created: netgrasp_event_wrapper.timestamp,
                    updated: netgrasp_event_wrapper.timestamp,
                };
                let interface_insert_query =
                    diesel::insert_into(interface::table).values(&new_interface);
                debug!(
                    "process_interface: interface_insert_query {}",
                    debug_query::<Sqlite, _>(&interface_insert_query).to_string()
                );
                interface_insert_query
                    .execute(&self.sql)
                    .expect("Error adding interface");

                // Recursively determine the interface_id we just added.
                netgrasp_event_wrapper =
                    self.process_interface(netgrasp_event_wrapper, interface, interface_ip);
                netgrasp_event_wrapper
            }
        }
    }

    fn vendor_id_helper(
        &self,
        netgrasp_event_wrapper: &NetgraspEventWrapper,
        is_source: bool,
    ) -> i32 {
        if is_source {
            netgrasp_event_wrapper.source.vendor.vendor_id
        } else {
            netgrasp_event_wrapper.target.vendor.vendor_id
        }
    }

    // Populate mac details in event wrapper, adding if new
    fn process_mac(
        &self,
        mut netgrasp_event_wrapper: NetgraspEventWrapper,
        mac_address: &str,
        is_self: i32,
        is_source: bool,
    ) -> NetgraspEventWrapper {
        trace!("process_mac: {}", mac_address);
        use crate::db::schema::mac;

        // Load vendor first so we can populate vendor_id
        netgrasp_event_wrapper =
            self.process_vendor(netgrasp_event_wrapper, mac_address, is_source);

        let mac_query = mac::table.filter(mac::address.eq(mac_address));
        debug!(
            "load_mac_id: {}",
            debug_query::<Sqlite, _>(&mac_query).to_string()
        );
        match mac_query.get_result::<Mac>(&self.sql) {
            // Return mac if exists
            Ok(m) => {
                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::MacSeen);
                if is_source {
                    netgrasp_event_wrapper.source.mac = m;
                } else {
                    netgrasp_event_wrapper.target.mac = m;
                }
                netgrasp_event_wrapper
            }
            // Otherwise this is the first time we've seen this vendor.
            Err(_) => {
                // If this mac address doesn't exist, add it.
                info!("new mac_address({})", mac_address);
                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::MacFirstSeen);

                // Load vendor details, necessary to set the correct vendor_id
                let new_mac = NewMac {
                    vendor_id: self.vendor_id_helper(&netgrasp_event_wrapper, is_source),
                    address: mac_address.to_string(),
                    is_self: is_self,
                    created: netgrasp_event_wrapper.timestamp,
                    updated: netgrasp_event_wrapper.timestamp,
                };
                let mac_insert_query = diesel::insert_into(mac::table).values(&new_mac);
                debug!(
                    "process_mac: insert {}",
                    debug_query::<Sqlite, _>(&mac_insert_query).to_string()
                );
                mac_insert_query
                    .execute(&self.sql)
                    .expect("Error adding mac");

                // Recursively determine the mac_id we just added.
                netgrasp_event_wrapper =
                    self.process_mac(netgrasp_event_wrapper, mac_address, is_self, is_source);
                netgrasp_event_wrapper
            }
        }
    }

    fn process_vendor(
        &self,
        mut netgrasp_event_wrapper: NetgraspEventWrapper,
        mac_address: &str,
        is_source: bool,
    ) -> NetgraspEventWrapper {
        trace!("process_vendor: {}", &mac_address);
        use crate::db::schema::vendor;

        let formatted_mac_address = MacAddress::parse_str(mac_address).unwrap();
        let vendor = self.oui.query_by_mac(&formatted_mac_address).unwrap();
        let vendor_name;
        let vendor_full_name;
        match vendor {
            Some(details) => {
                vendor_name = details.name_short;
                match details.name_long {
                    Some(name) => {
                        vendor_full_name = name;
                    }
                    None => {
                        vendor_full_name = vendor_name.to_string();
                    }
                }
            }
            None => {
                // @TODO: Review these, perhaps perform a remote API call as a backup?
                vendor_name = "unknown".to_string();
                vendor_full_name = "unknown".to_string();
                debug!("no vendor found for mac_address({})", mac_address);
            }
        }

        let vendor_query = vendor::table
            .filter(vendor::name.eq(&vendor_name))
            .filter(vendor::full_name.eq(&vendor_full_name));
        debug!(
            "load_vendor_id: {}",
            debug_query::<Sqlite, _>(&vendor_query).to_string()
        );
        match vendor_query.get_result::<Vendor>(&self.sql) {
            // If the vendor exists, return vendor_id.
            Ok(v) => {
                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::VendorSeen);
                if is_source {
                    netgrasp_event_wrapper.source.vendor = v;
                } else {
                    netgrasp_event_wrapper.target.vendor = v;
                }
                netgrasp_event_wrapper
            }
            // Otherwise this is the first time we've seen this vendor.
            Err(_) => {
                info!("new vendor({} [{}])", &vendor_full_name, &vendor_name);

                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::VendorFirstSeen);

                let new_vendor = NewVendor {
                    name: vendor_name,
                    full_name: vendor_full_name,
                    created: netgrasp_event_wrapper.timestamp,
                    updated: netgrasp_event_wrapper.timestamp,
                };
                let insert_vendor_query = diesel::insert_into(vendor::table).values(&new_vendor);
                debug!(
                    "load_vendor_id: insert new vendor: {}",
                    debug_query::<Sqlite, _>(&insert_vendor_query).to_string()
                );
                match insert_vendor_query.execute(&self.sql) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Error inserting vendor into database: [{}]", e);
                        // We have to exit or we'll get into an infinite loop.
                        std::process::exit(1);
                    }
                }

                netgrasp_event_wrapper =
                    self.process_vendor(netgrasp_event_wrapper, mac_address, is_source);
                netgrasp_event_wrapper
            }
        }
    }

    fn process_ip(
        &self,
        mut netgrasp_event_wrapper: NetgraspEventWrapper,
        ip_address: &str,
        is_source: bool,
    ) -> NetgraspEventWrapper {
        use crate::db::schema::ip::dsl::*;
        use crate::db::schema::network_event;

        let wrapper_mac_id;
        let wrapper_mac;
        if is_source {
            wrapper_mac_id = netgrasp_event_wrapper.source.mac.mac_id;
            wrapper_mac = netgrasp_event_wrapper.source.mac.address.clone();
        } else {
            wrapper_mac_id = netgrasp_event_wrapper.target.mac.mac_id;
            wrapper_mac = netgrasp_event_wrapper.target.mac.address.clone();
        }

        let loaded_ip_id;
        // This packet didn't include a MAC, but we may be able to retreive it from the database
        if wrapper_mac_id == 0 {
            if !is_source {
                // Target has IP but no MAC, so this is a request to see who owns an IP
                netgrasp_event_wrapper
                    .events
                    .push(NetgraspEventType::IpRequest);
            }
            let load_ip_id_query = ip.filter(address.eq(ip_address));
            debug!(
                "process_ip: load_ip_id_query get mac_id {}",
                debug_query::<Sqlite, _>(&load_ip_id_query).to_string()
            );
            loaded_ip_id = load_ip_id_query.get_result::<Ip>(&self.sql);
        }
        // This packet includes a MAC, make sure we've already recorded it in the database
        else {
            let load_ip_id_query =
                sql_query("SELECT * FROM ip WHERE address = ? AND (mac_id = ? OR mac_id = 0)")
                    .bind::<Text, _>(ip_address)
                    .bind::<Integer, _>(wrapper_mac_id);
            debug!(
                "process_ip: load_ip_id_query 2 {}",
                debug_query::<Sqlite, _>(&load_ip_id_query).to_string()
            );
            loaded_ip_id = load_ip_id_query.get_result::<Ip>(&self.sql);
        }

        // Process result to determine if we're seeing the mac or ip for the first time
        match loaded_ip_id {
            Ok(mut i) => {
                // Successful query means the ip already exists in the database, store appropriately
                if wrapper_mac_id != 0 {
                    // We've seen the mac before, but this is the first time seeing the ip and mac together
                    if i.mac_id == 0 {
                        netgrasp_event_wrapper
                            .events
                            .push(NetgraspEventType::IpFirstSeen);
                        netgrasp_event_wrapper
                            .events
                            .push(NetgraspEventType::DeviceFirstSeen);
                        i.mac_id = wrapper_mac_id;
                        let update_ip_set_mac_id_query =
                            diesel::update(ip).filter(address.eq(ip_address)).set((
                                mac_id.eq(wrapper_mac_id),
                                updated.eq(&netgrasp_event_wrapper.timestamp),
                            ));
                        debug!(
                            "process_ip: update_ip_set_mac_id_query {}",
                            debug_query::<Sqlite, _>(&update_ip_set_mac_id_query).to_string()
                        );
                        match update_ip_set_mac_id_query.execute(&self.sql) {
                            Err(e) => {
                                // Unexecpted error, exit to avoid an infinite loop.
                                // @TODO graceful error handling?
                                error!("Error updating ip table: [{}]", e);
                                std::process::exit(1);
                            }
                            Ok(_) => (),
                        }
                    }
                    // We've seen this ip and mac together before, check if we've seen it recently
                    else {
                        let previously_seen_query = network_event::table
                            .select(network_event::created)
                            .filter(network_event::ip_id.eq(&i.ip_id))
                            .order(network_event::created.desc())
                            .limit(2);
                        debug!(
                            "process_ip: previously_seen_query {}",
                            debug_query::<Sqlite, _>(&previously_seen_query).to_string()
                        );
                        let now = time::timestamp_now();
                        let inactive_before: i32 = (now - IPS_ACTIVE_FOR) as i32;
                        let previously_seen: i32 = match previously_seen_query.get_result(&self.sql)
                        {
                            Ok(p) => p,
                            Err(_) => now as i32,
                        };
                        if previously_seen < inactive_before {
                            netgrasp_event_wrapper
                                .events
                                .push(NetgraspEventType::IpReturned);
                            netgrasp_event_wrapper
                                .events
                                .push(NetgraspEventType::DeviceReturned);
                        }
                    }
                } else {
                    if is_source {
                        netgrasp_event_wrapper
                            .events
                            .push(NetgraspEventType::IpSeen);
                        netgrasp_event_wrapper
                            .events
                            .push(NetgraspEventType::DeviceSeen);
                    }
                }

                // if the hostname hasn't been updated in the past hour, perform a dns lookup
                // @TODO respect DNS TTL
                if i.updated > (time::elapsed(3600) as i32) {
                    let addr: std::net::IpAddr = match ip_address.parse() {
                        Ok(i) => i,
                        Err(e) => {
                            error!("Error parsing ip_address {}: [{}]", &ip_address, e);
                            // @TODO: how should we handle this gracefully?
                            return netgrasp_event_wrapper;
                        }
                    };
                    let hostname: String = match lookup_addr(&addr) {
                        Ok(h) => h,
                        Err(e) => {
                            warn!(
                                "Failed to look up host_name for ip_address {}: [{}]",
                                &ip_address, e
                            );
                            "unknown".to_string()
                        }
                    };
                    let timestamp = time::timestamp_now() as i32;
                    let update_ip_query = diesel::update(ip.filter(ip_id.eq(i.ip_id)))
                        .set((host_name.eq(&hostname), updated.eq(timestamp)));
                    debug!(
                        "process_ip: update_ip_query {}",
                        debug_query::<Sqlite, _>(&update_ip_query).to_string()
                    );
                    match update_ip_query.execute(&self.sql) {
                        // failed to update ip object
                        Err(e) => error!("process_ip: update_ip_query error: {}", e),
                        // successfully updated ip object
                        Ok(_) => {
                            if i.host_name != hostname {
                                i.host_name = hostname;
                                netgrasp_event_wrapper
                                    .events
                                    .push(NetgraspEventType::IpHostnameChanged);
                            }
                            i.updated = timestamp;
                        }
                    }
                }

                // store the ip object in the event wrapper
                if is_source {
                    netgrasp_event_wrapper.source.ip = i.clone();
                } else {
                    netgrasp_event_wrapper.target.ip = i.clone();
                }
            }
            // ip does not exist in database, add it
            Err(_) => {
                if wrapper_mac_id == 0 {
                    netgrasp_event_wrapper
                        .events
                        .push(NetgraspEventType::IpFirstRequest);
                } else {
                    netgrasp_event_wrapper
                        .events
                        .push(NetgraspEventType::IpFirstSeen);
                    netgrasp_event_wrapper
                        .events
                        .push(NetgraspEventType::DeviceFirstSeen);
                }

                let addr: std::net::IpAddr = match ip_address.parse() {
                    Ok(i) => i,
                    Err(e) => {
                        error!("Error parsing ip_address {}: [{}]", &ip_address, e);
                        // @TODO: how should we handle this gracefully?
                        return netgrasp_event_wrapper;
                    }
                };
                let hostname: String = match lookup_addr(&addr) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(
                            "Failed to look up host_name for ip_address {}: [{}]",
                            &ip_address, e
                        );
                        "unknown".to_string()
                    }
                };

                info!(
                    "new ip({}) hostname({}) with mac({})",
                    &ip_address, &hostname, &wrapper_mac
                );
                let new_ip = NewIp {
                    mac_id: wrapper_mac_id,
                    address: ip_address.to_string(),
                    host_name: hostname,
                    custom_name: "".to_string(),
                    created: netgrasp_event_wrapper.timestamp,
                    updated: netgrasp_event_wrapper.timestamp,
                };
                let insert_ip_query = diesel::insert_into(ip).values(&new_ip);
                debug!(
                    "load_ip_id: insert_ip_query {}",
                    debug_query::<Sqlite, _>(&insert_ip_query).to_string()
                );
                match insert_ip_query.execute(&self.sql) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Error inserting ip into database: [{}]", e);
                        // exit to avoid an infinte loop
                        // @TODO: handle this gracefully?
                        std::process::exit(1);
                    }
                }

                // Recursively determine the ip_id of the IP address we just added.
                netgrasp_event_wrapper =
                    self.process_ip(netgrasp_event_wrapper, &ip_address, is_source);
            }
        }

        netgrasp_event_wrapper
    }

    fn process_event(
        &self,
        netgrasp_event_type: &NetgraspEventType,
        netgrasp_event_wrapper: &NetgraspEventWrapper,
    ) {
        use crate::db::schema::ip;
        use crate::db::schema::mac;
        use crate::db::schema::network_event::dsl::*;
        use crate::db::schema::vendor;
        use std::convert::TryInto;

        let event_detail = netgrasp_event_detail(netgrasp_event_type);
        debug!(
            "process_event: priority: {}, name: {}, description: {}",
            &event_detail.priority, &event_detail.name, &event_detail.description
        );

        if event_detail.priority >= self.minimum_priority {
            // Determine how many times the IP was seen recently.
            debug_assert!(netgrasp_event_wrapper.network_event.ip_id > 0);
            let now = time::timestamp_now();
            let inactive_before: i32 = (now - IPS_ACTIVE_FOR) as i32;
            let recently_seen_count = diesel::dsl::sql::<diesel::sql_types::BigInt>("COUNT(ip_id)");
            let recently_seen_query = network_event
                .select(recently_seen_count)
                .filter(ip_id.eq(&netgrasp_event_wrapper.network_event.ip_id))
                .filter(created.ge(inactive_before));
            debug!(
                "process_event: recently_seen_query: {}",
                debug_query::<Sqlite, _>(&recently_seen_query).to_string()
            );
            let recently_seen: i64 = match recently_seen_query.load(&self.sql) {
                Ok(r) => *r.first().unwrap(),
                Err(_) => 0,
            };
            debug!("process_event: recently_seen: {}", recently_seen);

            let recently_seen_string: String;
            if recently_seen == 1 {
                recently_seen_string = "1 time".to_string();
            } else if recently_seen == 0 {
                recently_seen_string = "never".to_string();
            } else {
                recently_seen_string = format!("{} times", recently_seen);
            }
            debug!(
                "process_event: recently_seen_string: {}",
                recently_seen_string
            );

            // Determine the last time the IP was seen recently.
            let previously_seen_query = network_event
                .select(created)
                .filter(ip_id.eq(&netgrasp_event_wrapper.network_event.ip_id))
                .order(created.desc())
                .limit(2);
            debug!(
                "process_event: previously_seen_query: {}",
                debug_query::<Sqlite, _>(&previously_seen_query).to_string()
            );
            // @TODO: what if only 1 is returned?
            // convert i32 timestamp from SQLite into u64 for helpers
            let previously_seen_string: String = match previously_seen_query.load(&self.sql) {
                Ok(l) => {
                    let timestamp_string: String = match l.last() {
                        Some(t) => {
                            let g: i32 = *t;
                            let timestamp: u64 =
                                g.try_into().expect("failed to convert i32 to u64");
                            format::time_ago(timestamp, true)
                        }
                        None => "never".to_string(),
                    };
                    timestamp_string
                }
                Err(_) => "never".to_string(),
            };
            debug!(
                "process_event: previously_seen_string: {}",
                previously_seen_string
            );

            // Determine the first time the IP was seen.
            let min_created = diesel::dsl::sql::<diesel::sql_types::Integer>("MIN(created)");
            let first_seen_query = network_event
                .select(min_created)
                .filter(ip_id.eq(&netgrasp_event_wrapper.network_event.ip_id));
            debug!(
                "process_event: first_seen_query: {}",
                debug_query::<Sqlite, _>(&first_seen_query).to_string()
            );
            // convert i32 timestamp from SQLite into u64 for helpers
            let first_seen: u64 = match first_seen_query.load(&self.sql) {
                Ok(l) => {
                    let timestamp: i32 = *l.first().unwrap();
                    timestamp.try_into().expect("failed to convert i32 to u64")
                }
                Err(_) => time::timestamp_now(),
            };
            debug!("process_event: first_seen: {}", first_seen);

            let devices_talked_to_count_query = sql_query("SELECT COUNT(DISTINCT(tgt_ip_id)) AS counter FROM network_event WHERE ip_id = ? AND created >= ? AND tgt_ip_id > 0")
                .bind::<Integer, _>(&netgrasp_event_wrapper.network_event.ip_id)
                .bind::<Integer, _>(time::elapsed(86400) as i32);
            debug!(
                "process_event: devices_talked_to_query: {}",
                debug_query::<Sqlite, _>(&devices_talked_to_count_query).to_string()
            );
            let devices_talked_to_count: TalkedToCount = match devices_talked_to_count_query.get_result::<TalkedToCount>(&self.sql) {
                Ok(count) => count,
                Err(e) => {
                    warn!("process_event; devices_talked_to_count_query error: {}", e);
                    TalkedToCount {
                        counter: 0
                    }
                }
            };

            let mut talked_to_list: Vec<TalkedToDisplay> = vec![];
            if devices_talked_to_count.counter > 0 {
                // build list of devices that have been talked to
                let devices_talked_to_query = sql_query("SELECT MAX(tgt_mac_id) AS tgt_mac_id, tgt_ip_id, COUNT(tgt_ip_id) AS count FROM network_event WHERE ip_id = ? AND created >= ? AND tgt_ip_id > 0 GROUP BY tgt_ip_id ORDER BY count DESC LIMIT ?")
                    .bind::<Integer, _>(&netgrasp_event_wrapper.network_event.ip_id)
                    .bind::<Integer, _>(time::elapsed(86400) as i32)
                    .bind::<Integer, _>(MAX_DEVICES_TO_LIST);
                debug!(
                    "process_event: devices_talked_to_query: {}",
                    debug_query::<Sqlite, _>(&devices_talked_to_query).to_string()
                );
                let devices_talked_to: Vec<TalkedTo> = match devices_talked_to_query.load(&self.sql) {
                    Ok(talked_to) => talked_to,
                    Err(e) => {
                        warn!("process_event; devices_talked_to_query error: {}", e);
                        vec![TalkedTo {
                            tgt_mac_id: 0,
                            tgt_ip_id: netgrasp_event_wrapper.source.ip.ip_id,
                            count: 1,
                        }]
                    }
                };

                for device in &devices_talked_to {
                    let ip_query = ip::table
                        .select((
                            ip::address,
                            ip::host_name,
                            ip::custom_name,
                            ip::mac_id,
                        ))
                        .filter(ip::ip_id.eq(device.tgt_ip_id))
                        .limit(1);
                    debug!(
                        "process_event: ip_query: {}",
                        debug_query::<Sqlite, _>(&ip_query).to_string()
                    );
                    let ip_detail: IpDetail = match ip_query.get_result(&self.sql) {
                        Ok(i) => i,
                        Err(e) => {
                            warn!("process_event; ip_query error: {}", e);
                            IpDetail {
                                address: netgrasp_event_wrapper.source.ip.address.to_string(),
                                host_name: netgrasp_event_wrapper.source.ip.host_name.to_string(),
                                custom_name: netgrasp_event_wrapper.source.ip.custom_name.to_string(),
                                mac_id: netgrasp_event_wrapper.source.mac.mac_id,
                            }
                        }
                    };

                    // try to query mac details, if this fails default to "unknown"
                    let mac_query = mac::table
                        .inner_join(vendor::table)
                        .select((
                            mac::address,
                            vendor::full_name,
                        ))
                        .filter(mac::mac_id.eq(ip_detail.mac_id))
                        .limit(1);
                    debug!(
                        "process_event: mac_query: {}",
                        debug_query::<Sqlite, _>(&mac_query).to_string()
                    );
                    let mac_detail: MacDetail = match mac_query.get_result(&self.sql) {
                        Ok(m) => m,
                        Err(e) => {
                            // if tgt_mac_id is 0 we'll default to "unknown"
                            debug!("process_event; mac_query error: {}", e);
                            MacDetail {
                                address: "unknown".to_string(),
                                full_name: "unknown".to_string(),
                            }
                        }
                    };

                    let talked_to = format::device_name(format::DeviceName {
                                custom_name: ip_detail.custom_name.to_string(),
                                host_name: ip_detail.host_name.to_string(),
                                ip_address: ip_detail.address.to_string(),
                                vendor_full_name: mac_detail.full_name.to_string(),
                            });
                    if device.count == 1 {
                        if ip_detail.mac_id > 0 {
                            talked_to_list.push(TalkedToDisplay {
                                name: talked_to,
                                count: device.count,
                                count_string: "1 time".to_string(),
                            });
                        }
                        else {
                            talked_to_list.push(TalkedToDisplay {
                                name: talked_to,
                                count: device.count,
                                count_string: "1 time - no reply".to_string(),
                            });
                        }
                    }
                    else {
                        if ip_detail.mac_id > 0 {
                            talked_to_list.push(TalkedToDisplay {
                                name: talked_to,
                                count: device.count,
                                count_string: format!("{} times", device.count),
                            });
                        }
                        else {
                            talked_to_list.push(TalkedToDisplay {
                                name: talked_to,
                                count: device.count,
                                count_string: format!("{} times - no replies", device.count),
                            });
                        }
                    }
                }
            }

            let devices_talked_to_count_string: String;
            if devices_talked_to_count.counter == 1 {
                devices_talked_to_count_string = "1 device".to_string();
            } else {
                devices_talked_to_count_string = format!("{} devices", devices_talked_to_count.counter);
            }
            debug!(
                "process_event: devices_talked_to_count_string: {:?}",
                devices_talked_to_count_string
            );

            let mut notification = Notification::init("Netgrasp", "", &event_detail.description);
            notification.add_value("event".to_string(), event_detail.name);
            notification.add_value(
                "name".to_string(),
                get_device_name(&netgrasp_event_wrapper, true),
            );
            notification.add_value(
                "ip".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.source.ip.address),
            );
            notification.add_value(
                "mac".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.source.mac.address),
            );
            notification.add_value(
                "host_name".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.source.ip.host_name),
            );
            notification.add_value(
                "vendor_name".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.source.vendor.name),
            );
            notification.add_value(
                "vendor_full_name".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.source.vendor.full_name),
            );
            notification.add_value("detail".to_string(), event_detail.description);
            notification.add_value(
                "interface".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.interface.label),
            );
            notification.add_value(
                "interface_ip".to_string(),
                name_or_unknown(&netgrasp_event_wrapper.interface.address),
            );
            notification.add_value("first_seen".to_string(), format::time_ago(first_seen, true));
            notification.add_value("previously_seen".to_string(), previously_seen_string);
            notification.add_value("recently_seen".to_string(), recently_seen_string);
            notification.add_value(
                "devices_talked_to_count".to_string(),
                devices_talked_to_count.counter.to_string(),
            );
            notification.add_value(
                "devices_talked_to_count_string".to_string(),
                devices_talked_to_count_string.to_string(),
            );
            notification
                .add_serde_json_value("devices_talked_to".to_string(), to_json(&talked_to_list));
            notification.set_title_template(templates::NETGRASP_TITLE_TEMPLATE.to_string());
            
            // start building the templates
            let text_template = templates::NETGRASP_TEXT_TEMPLATE.to_string();
            let html_template = templates::NETGRASP_HTML_TEMPLATE.to_string();

            // add block for devices talked to
            let text_inner_template: String;
            let html_inner_template: String;
            if devices_talked_to_count.counter > 0 {
                text_inner_template = text_template + templates::NETGRASP_TEXT_TALKED_TO_TEMPLATE;
                html_inner_template = html_template + templates::NETGRASP_HTML_TALKED_TO_TEMPLATE;
            }
            else {
                text_inner_template = text_template;
                html_inner_template = html_template;
            }

            // finish building the templates
            let text_template = text_inner_template + templates::NETGRASP_TEXT_FOOTER_TEMPLATE;
            let html_template = html_inner_template + templates::NETGRASP_HTML_FOOTER_TEMPLATE;

            notification.set_short_text_template(text_template.clone());
            notification.set_short_html_template(html_template.clone());
            notification.set_long_text_template(text_template);
            notification.set_long_html_template(html_template);
            debug!("process_event: notification({:?})", &notification);
            // @TODO this clearly needs to be configurable
            let server = "http://localhost:8000";
            match notification.send(&server, event_detail.priority, 0, None) {
                Err(e) => error!("process_event: failed to send notification '{}': {:?}", &notification.title, e),
                Ok(_) => info!("process_event: notification '{}' with priority {} sent to {}", &notification.title, event_detail.priority, &server),
            };
        }
    }

    // Returns a vector of all currently known active devices.
    pub fn get_active_devices(&self) -> Vec<NetgraspActiveDevice> {
        use crate::db::schema::interface;
        use crate::db::schema::ip;
        use crate::db::schema::mac;
        use crate::db::schema::network_event::dsl::*;
        use crate::db::schema::vendor;

        let min_updated =
            diesel::dsl::sql::<diesel::sql_types::Integer>("MIN(network_event.updated)");
        let max_updated =
            diesel::dsl::sql::<diesel::sql_types::Integer>("MAX(network_event.updated)");
        let count_src_ip =
            diesel::dsl::sql::<diesel::sql_types::BigInt>("COUNT(network_event.ip_id)");
        let active_devices_query = network_event
            .inner_join(interface::table)
            .inner_join(mac::table)
            .inner_join(vendor::table)
            .inner_join(ip::table)
            .select((
                interface::label,
                ip::address,
                mac::address,
                ip::host_name,
                vendor::name,
                vendor::full_name,
                ip::custom_name,
                &count_src_ip,
                min_updated,
                &max_updated,
            ))
            .filter(ip_id.ne(0))
            .filter(recent.eq(1))
            .group_by(ip_id)
            .order((max_updated.clone().desc(), count_src_ip.clone().desc()));
        debug!(
            "get_active_devices: {}",
            debug_query::<Sqlite, _>(&active_devices_query).to_string()
        );
        let active_devices: Vec<(NetgraspActiveDevice)> = match active_devices_query.load(&self.sql)
        {
            Ok(a) => a,
            Err(e) => {
                error!("Error loading active devices: [{}]", e);
                vec![NetgraspActiveDevice::default()]
            }
        };
        debug!(
            "get_active_devices: {} active devices",
            active_devices.len()
        );
        active_devices
    }

    /// Helper function that fully populates a network_event_wrapper which only contains
    /// a network_event object (ie, loaded from the database).
    fn populate_network_event(
        &self,
        mut netgrasp_event_wrapper: NetgraspEventWrapper,
    ) -> NetgraspEventWrapper {
        use crate::db::schema::interface;
        use crate::db::schema::ip;
        use crate::db::schema::mac;
        use crate::db::schema::vendor;

        netgrasp_event_wrapper.timestamp = netgrasp_event_wrapper.network_event.updated;
        if netgrasp_event_wrapper.network_event.interface_id != 0 {
            let load_interface_query = interface::table.filter(
                interface::interface_id.eq(netgrasp_event_wrapper.network_event.interface_id),
            );
            debug!(
                "populate_network_event: load_interface_query {}",
                debug_query::<Sqlite, _>(&load_interface_query).to_string()
            );
            netgrasp_event_wrapper.interface =
                match load_interface_query.get_result::<Interface>(&self.sql) {
                    Ok(i) => i,
                    Err(e) => {
                        error!(
                            "populate_network_event: unexpected error loading interface: {}",
                            e
                        );
                        // this shouldn't happen, exit
                        std::process::exit(1);
                    }
                };
        }
        if netgrasp_event_wrapper.network_event.mac_id != 0 {
            let load_mac_query =
                mac::table.filter(mac::mac_id.eq(netgrasp_event_wrapper.network_event.mac_id));
            debug!(
                "populate_network_event: load_mac_query {}",
                debug_query::<Sqlite, _>(&load_mac_query).to_string()
            );
            netgrasp_event_wrapper.source.mac = match load_mac_query.get_result::<Mac>(&self.sql) {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        "populate_network_event: unexpected error loading mac: {}",
                        e
                    );
                    // this shouldn't happen, exit
                    std::process::exit(1);
                }
            };
        }
        if netgrasp_event_wrapper.network_event.vendor_id != 0 {
            let load_vendor_query = vendor::table
                .filter(vendor::vendor_id.eq(netgrasp_event_wrapper.network_event.vendor_id));
            debug!(
                "populate_network_event: load_vendor_query {}",
                debug_query::<Sqlite, _>(&load_vendor_query).to_string()
            );
            netgrasp_event_wrapper.source.vendor =
                match load_vendor_query.get_result::<Vendor>(&self.sql) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "populate_network_event: unexpected error loading vendor: {}",
                            e
                        );
                        // this shouldn't happen, exit
                        std::process::exit(1);
                    }
                };
        }
        if netgrasp_event_wrapper.network_event.ip_id != 0 {
            let load_ip_query =
                ip::table.filter(ip::ip_id.eq(netgrasp_event_wrapper.network_event.ip_id));
            debug!(
                "populate_network_event: load_ip_query {}",
                debug_query::<Sqlite, _>(&load_ip_query).to_string()
            );
            netgrasp_event_wrapper.source.ip = match load_ip_query.get_result::<Ip>(&self.sql) {
                Ok(i) => i,
                Err(e) => {
                    error!("populate_network_event: unexpected error loading ip: {}", e);
                    // this shouldn't happen, exit
                    std::process::exit(1);
                }
            };
        }
        if netgrasp_event_wrapper.network_event.tgt_mac_id != 0 {
            let load_mac_query =
                mac::table.filter(mac::mac_id.eq(netgrasp_event_wrapper.network_event.tgt_mac_id));
            debug!(
                "populate_network_event: load_mac_query {}",
                debug_query::<Sqlite, _>(&load_mac_query).to_string()
            );
            netgrasp_event_wrapper.target.mac = match load_mac_query.get_result::<Mac>(&self.sql) {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        "populate_network_event: unexpected error loading target mac: {}",
                        e
                    );
                    // this shouldn't happen, exit
                    std::process::exit(1);
                }
            };
        }
        if netgrasp_event_wrapper.network_event.tgt_vendor_id != 0 {
            let load_vendor_query = vendor::table
                .filter(vendor::vendor_id.eq(netgrasp_event_wrapper.network_event.tgt_vendor_id));
            debug!(
                "populate_network_event: load_vendor_query {}",
                debug_query::<Sqlite, _>(&load_vendor_query).to_string()
            );
            netgrasp_event_wrapper.target.vendor =
                match load_vendor_query.get_result::<Vendor>(&self.sql) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "populate_network_event: unexpected error loading target vendor: {}",
                            e
                        );
                        // this shouldn't happen, exit
                        std::process::exit(1);
                    }
                };
        }
        if netgrasp_event_wrapper.network_event.tgt_ip_id != 0 {
            let load_ip_query =
                ip::table.filter(ip::ip_id.eq(netgrasp_event_wrapper.network_event.tgt_ip_id));
            debug!(
                "populate_network_event: load_ip_query {}",
                debug_query::<Sqlite, _>(&load_ip_query).to_string()
            );
            netgrasp_event_wrapper.target.ip = match load_ip_query.get_result::<Ip>(&self.sql) {
                Ok(i) => i,
                Err(e) => {
                    error!(
                        "populate_network_event: unexpected error loading target ip: {}",
                        e
                    );
                    // this shouldn't happen, exit
                    std::process::exit(1);
                }
            };
        }
        netgrasp_event_wrapper
    }

    pub fn process_inactive_ips(&self) {
        use crate::db::schema::network_event::dsl::*;
        use diesel::*;

        let now = time::timestamp_now();
        let inactive_before: i32 = (now - IPS_ACTIVE_FOR) as i32;
        // 1) set 'recent' to 0 where created < active_seconds ago
        let update_network_event_query = diesel::update(network_event)
            .filter(created.le(inactive_before))
            .set((recent.eq(0), updated.eq(now as i32)));
        debug!(
            "process_inactive_ips: update_network_event_query: {}",
            debug_query::<Sqlite, _>(&update_network_event_query).to_string()
        );
        match update_network_event_query.execute(&self.sql) {
            Err(e) => {
                error!("unexpected error marking network_events inactive: {}", e);
                // this shouldn't happen, exit
                std::process::exit(1);
            }
            Ok(_) => (),
        }

        // 2a) identify expired ip adresses
        let inactive_ip_ids_query = sql_query("SELECT ip_id FROM network_event WHERE ip_id != 0 GROUP BY ip_id HAVING MAX(created) < ?")
            .bind::<Integer, _>(inactive_before);
        debug!(
            "process_inactive_ips: inactive_ip_ids_query: {}",
            debug_query::<Sqlite, _>(&inactive_ip_ids_query).to_string()
        );
        let inactive_ip_ids: Vec<DistinctIpId> =
            match inactive_ip_ids_query.load::<DistinctIpId>(&self.sql) {
                Ok(i) => i,
                Err(e) => {
                    error!(
                        "process_inactive_ips: unexpected error loading inactive ip ids: {}",
                        e
                    );
                    // this shouldn't happen, exit
                    std::process::exit(1);
                }
            };

        // 2b) identify the ips that have gone inactive (no recent packets)
        for inactive_ip_id in inactive_ip_ids {
            let inactive_ip_query = network_event
                .select((
                    recent,
                    processed,
                    interface_id,
                    mac_id,
                    vendor_id,
                    ip_id,
                    tgt_mac_id,
                    tgt_vendor_id,
                    tgt_ip_id,
                    created,
                    updated,
                ))
                .filter(ip_id.eq(inactive_ip_id.ip_id))
                .filter(processed.eq(0))
                .filter(recent.eq(0))
                .limit(1);
            debug!(
                "process_inactive_ips: inactive_ip_query: {}",
                debug_query::<Sqlite, _>(&inactive_ip_query).to_string()
            );
            match inactive_ip_query.get_result(&self.sql) {
                Ok(i) => {
                    let mut netgrasp_event_wrapper: NetgraspEventWrapper =
                        NetgraspEventWrapper::initialize(NetgraspEventWrapperType::Arp);
                    netgrasp_event_wrapper.network_event = i;
                    netgrasp_event_wrapper = self.populate_network_event(netgrasp_event_wrapper);
                    netgrasp_event_wrapper
                        .events
                        .push(NetgraspEventType::IpInactive);
                    netgrasp_event_wrapper
                        .events
                        .push(NetgraspEventType::DeviceInactive);
                    self.process_event(&NetgraspEventType::IpInactive, &netgrasp_event_wrapper);
                    self.process_event(&NetgraspEventType::DeviceInactive, &netgrasp_event_wrapper);
                }
                Err(e) => {
                    debug!(
                        "process_inactive_ips: failed to load inactive ip event details: {}",
                        e
                    );
                }
            }
        }

        // 3) Set processed = 1 for all is_active = 0 AND processed = 0
        let response = diesel::update(network_event)
            .filter(processed.eq(0))
            .filter(recent.eq(0))
            .set((processed.eq(1), updated.eq(now as i32)))
            .execute(&self.sql);
        match response {
            Err(e) => error!("unexpected error processing inactive ips: {}", e),
            Ok(_) => (),
        }
    }

    pub fn detect_netscan(&self, scan_range: u64) -> bool {
        use crate::db::schema::network_event::dsl::*;

        let mut detected_netscan = false;
        let load_netscan_query = sql_query("SELECT COUNT(DISTINCT tgt_ip_id) AS tgt_ip_id_count, ip_id FROM network_event WHERE created > ? GROUP BY ip_id HAVING tgt_ip_id_count > ?")
            .bind::<Integer, _>(time::elapsed(scan_range) as i32)
            // @TODO: expose as configuration how many devices talked to constitutes a netscan
            .bind::<Integer, _>(50);
        debug!(
            "detect_netscan: load_netscan_query: {}",
            debug_query::<Sqlite, _>(&load_netscan_query).to_string()
        );
        match load_netscan_query.get_results::<NetworkScan>(&self.sql) {
            Ok(netscans) => {
                if netscans.len() > 0 {
                    info!("detect_netscan: {} netscans", netscans.len());
                }
                for netscan in netscans {
                    let netscan_event_query = network_event
                        .select((
                            recent,
                            processed,
                            interface_id,
                            mac_id,
                            vendor_id,
                            ip_id,
                            tgt_mac_id,
                            tgt_vendor_id,
                            tgt_ip_id,
                            created,
                            updated,
                        ))
                        .filter(ip_id.eq(netscan.ip_id))
                        .limit(1);
                    debug!(
                        "detect_netscan: netscan_event_query: {}",
                        debug_query::<Sqlite, _>(&netscan_event_query).to_string()
                    );
                    match netscan_event_query.get_result(&self.sql) {
                        Ok(i) => {
                            info!(
                                "detect_netscan: netscan of {}+ devices",
                                netscan.tgt_ip_id_count
                            );
                            let mut netgrasp_event_wrapper: NetgraspEventWrapper =
                                NetgraspEventWrapper::initialize(NetgraspEventWrapperType::Arp);
                            netgrasp_event_wrapper.network_event = i;
                            netgrasp_event_wrapper =
                                self.populate_network_event(netgrasp_event_wrapper);
                            netgrasp_event_wrapper
                                .events
                                .push(NetgraspEventType::NetworkScan);
                            self.process_event(
                                &NetgraspEventType::NetworkScan,
                                &netgrasp_event_wrapper,
                            );
                            detected_netscan = true;
                        }
                        Err(e) => {
                            warn!(
                                "detect_netscan: failed to load netscan event details: {}",
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                debug!("detect_netscan: load_netscan_query: error: {}", e);
                return detected_netscan;
            }
        }
        detected_netscan
    }
}

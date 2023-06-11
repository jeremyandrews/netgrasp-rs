use async_once_cell::OnceCell;
use libarp::arp::ArpMessage;
use sea_orm::*;

use netgrasp_entity::{prelude::*, *};

use crate::NetgraspIp;

static DB: OnceCell<DatabaseConnection> = OnceCell::new();

pub(crate) async fn connection(database_url: &str) -> &DatabaseConnection {
    DB.get_or_init(async {
        match Database::connect(database_url).await {
            Ok(d) => d,
            Err(e) => {
                // @TODO: better error handling / perhaps retry.
                panic!("database error: {}", e);
            }
        }
    })
    .await
}

// Get database mac_id asociated with Mac hardware address.
pub(crate) async fn record_mac(database_url: &str, arp_message: &ArpMessage) -> Option<i32> {
    let mac = {
        let db = connection(database_url).await;
        match Mac::find()
            .filter(
                mac::Column::HardwareAddress.like(&arp_message.source_hardware_address.to_string()),
            )
            .one(db)
            .await
        {
            Ok(m) => m,
            Err(_) => return None,
        }
    };
    if let Some(m) = mac {
        Some(m.mac_id)
    } else {
        let new_mac = mac::ActiveModel {
            // @TODO: On SQLite this is apparently a string?
            //created: Set(chrono::Utc::now().naive_utc().to_owned()),
            created: Set(chrono::Utc::now().naive_utc().to_string()),
            hardware_address: Set(arp_message.source_hardware_address.to_string()),
            ..Default::default()
        };
        let new_mac_id = {
            let db = connection(database_url).await;
            Mac::insert(new_mac)
                .exec(db)
                .await
                .expect("failed to write mac to database")
        };
        Some(new_mac_id.last_insert_id)
    }
}

// Get database mac_id asociated with Mac hardware address.
pub(crate) async fn record_ip(database_url: &str, ip: &NetgraspIp<'_>) -> Option<i32> {
    let existing_ip = {
        let db = connection(database_url).await;
        match Ip::find()
            .filter(ip::Column::Interface.like(ip.interface))
            .filter(ip::Column::Address.like(ip.address))
            .one(db)
            .await
        {
            Ok(m) => m,
            Err(_) => return None,
        }
    };
    if let Some(existing) = existing_ip {
        Some(existing.ip_id)
    } else {
        let new_ip = ip::ActiveModel {
            // @TODO: On SQLite this is apparently a string?
            //created: Set(chrono::Utc::now().naive_utc().to_owned()),
            created: Set(chrono::Utc::now().naive_utc().to_string()),
            updated: Set(chrono::Utc::now().naive_utc().to_string()),
            interface: Set(ip.interface.to_string()),
            address: Set(ip.address.to_string()),
            host: Set(ip.host.map(str::to_string)),
            ..Default::default()
        };
        let new_ip_id = {
            let db = connection(database_url).await;
            Ip::insert(new_ip)
                .exec(db)
                .await
                .expect("failed to write mac to database")
        };
        Some(new_ip_id.last_insert_id)
    }
}

// Record arp activity.
pub(crate) async fn record_activity(
    database_url: &str,
    interface: &str,
    mac_id: i32,
    mac: String,
    device: Option<String>,
    ip_id: i32,
    ip: String,
    host: Option<String>,
) {
    //println!("{}: {} ({:?}) [{:?}]", interface, ip, host, device);

    let new_recent_activity = recent_activity::ActiveModel {
        // @TODO: On SQLite this is apparently a string?
        //timestamp: Set(chrono::Utc::now().naive_utc().to_owned()),
        timestamp: Set(chrono::Utc::now().naive_utc().to_string()),
        interface: Set(interface.to_string()),
        mac_id: Set(mac_id),
        mac: Set(mac),
        vendor: Set(device),
        ip_id: Set(ip_id),
        ip: Set(ip),
        host: Set(host),
        ..Default::default()
    };

    let db = connection(database_url).await;
    RecentActivity::insert(new_recent_activity)
        .exec(db)
        .await
        .expect("failed to write activity to database");

    let new_activity_log = activity_log::ActiveModel {
        // @TODO: On SQLite this is apparently a string?
        //timestamp: Set(chrono::Utc::now().naive_utc().to_owned()),
        timestamp: Set(chrono::Utc::now().naive_utc().to_string()),
        interface: Set(interface.to_string()),
        mac_id: Set(mac_id),
        ip_id: Set(ip_id),
        ..Default::default()
    };

    let db = connection(database_url).await;
    ActivityLog::insert(new_activity_log)
        .exec(db)
        .await
        .expect("failed to write activity to database");
}

#[derive(FromQueryResult, Debug)]
pub struct ActiveDevice {
    pub interface: String,
    pub mac: String,
    pub vendor: Option<String>,
    pub ip: String,
    pub host: Option<String>,
    pub custom: Option<String>,
    pub recently_seen_count: i32,
    pub recently_seen_first: String,
    pub recently_seen_last: String,
}

pub(crate) async fn get_active_devices(database_url: &str) -> Vec<ActiveDevice> {
    let db = connection(database_url).await;
    match recent_activity::Entity::find()
        .column_as(recent_activity::Column::Interface, "interface")
        .column_as(recent_activity::Column::Mac, "mac")
        .column_as(recent_activity::Column::Vendor, "vendor")
        .column_as(recent_activity::Column::Ip, "ip")
        .column_as(recent_activity::Column::Host, "host")
        .column_as(recent_activity::Column::Custom, "custom")
        .column_as(
            recent_activity::Column::RecentActivityId.count(),
            "recently_seen_count",
        )
        .column_as(
            recent_activity::Column::Timestamp.min(),
            "recently_seen_first",
        )
        .column_as(
            recent_activity::Column::Timestamp.max(),
            "recently_seen_last",
        )
        .group_by(recent_activity::Column::Interface)
        .group_by(recent_activity::Column::Ip)
        .order_by_asc(recent_activity::Column::Timestamp.max())
        .into_model::<ActiveDevice>()
        .all(db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("get_active_devices query error: {}", e);
            Vec::new()
        }
    }
}

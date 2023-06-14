// Interaction with database layer.

use async_once_cell::OnceCell;
use chrono::Duration;
use libarp::arp::ArpMessage;
use sea_orm::*;

use netgrasp_entity::{prelude::*, *};

use crate::recent_activity::Model;
use crate::NetgraspIp;

static DB: OnceCell<DatabaseConnection> = OnceCell::new();

#[derive(FromQueryResult, Debug)]
pub(crate) struct DeviceSeen {
    pub(crate) seen_count: i32,
    pub(crate) seen_recently: Option<String>,
    pub(crate) seen_first: String,
}

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

pub(crate) async fn get_custom(database_url: &str, mac_id: i32) -> Option<String> {
    let db = connection(database_url).await;
    let custom_name = custom::Entity::find()
        .filter(custom::Column::MacId.eq(mac_id))
        .one(db)
        .await
        .expect("failed to query custom table");
    if let Some(name) = custom_name {
        Some(name.name)
    } else {
        None
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
        custom: Set(get_custom(database_url, mac_id).await),
        audited: Set(0),
        ..Default::default()
    };

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
    RecentActivity::insert(new_recent_activity)
        .exec(db)
        .await
        .expect("failed to write activity to database");
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
    let active_duration = Duration::minutes(crate::MINUTES_ACTIVE_FOR);
    let active_timestamp = chrono::Utc::now()
        .naive_utc()
        .checked_sub_signed(active_duration)
        .unwrap()
        .to_string();
    match recent_activity::Entity::find()
        .filter(recent_activity::Column::Timestamp.gt(active_timestamp))
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
        .group_by(recent_activity::Column::Mac)
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

// Get a list of all MAC's found in recent_activity.
pub(crate) async fn get_active_macs(database_url: &str) -> Vec<Model> {
    let db = connection(&database_url).await;
    match recent_activity::Entity::find()
        // Consider each recently seen Mac a single time.
        .group_by(recent_activity::Column::MacId)
        // Start with most recently seen first.
        .order_by_desc(recent_activity::Column::Timestamp.max())
        .all(db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("list all mac addresses query error: {}", e);
            Vec::new()
        }
    }
}

// Returns bool indicating whether or not a MAC has been assigned a custom name.
pub(crate) async fn is_identified_mac(database_url: &str, mac_id: i32) -> bool {
    let db = connection(&database_url).await;
    match custom::Entity::find()
        .filter(custom::Column::MacId.eq(mac_id))
        .one(db)
        .await
    {
        Ok(m) => m.is_some(),
        Err(e) => {
            eprintln!("find unidentified mac addresses query error: {}", e);
            false
        }
    }
}

pub(crate) async fn get_mac_stats(database_url: &str, mac: &str) -> Option<DeviceSeen> {
    let db = connection(&database_url).await;
    recent_activity::Entity::find()
        .left_join(Mac)
        .filter(recent_activity::Column::Mac.contains(&mac))
        .filter(recent_activity::Column::Audited.eq(1))
        .group_by(recent_activity::Column::Mac)
        .column_as(
            recent_activity::Column::RecentActivityId.count(),
            "seen_count",
        )
        .column_as(recent_activity::Column::Timestamp.max(), "seen_recently")
        .column_as(mac::Column::Created, "seen_first")
        .into_model::<DeviceSeen>()
        .one(db)
        .await
        .expect("failed to poll timestamp information")
}

pub(crate) async fn record_custom(
    database_url: &str,
    mac_id: i32,
    ip_id: i32,
    custom: &str,
) -> bool {
    let db = connection(&database_url).await;
    let existing = Custom::find()
        .filter(custom::Column::MacId.eq(mac_id))
        .one(db)
        .await
        .expect("failed to query cutom table");

    if let Some(existing) = existing {
        let mut existing_custom: custom::ActiveModel = existing.into();
        existing_custom.updated = Set(chrono::Utc::now().naive_utc().to_string());
        existing_custom.name = Set(custom.to_string());
        existing_custom
            .update(db)
            .await
            .expect("failed to update custom");
    } else {
        let new_custom = custom::ActiveModel {
            created: Set(chrono::Utc::now().naive_utc().to_string()),
            updated: Set(chrono::Utc::now().naive_utc().to_string()),
            mac_id: Set(mac_id),
            ip_id: Set(ip_id),
            name: Set(custom.to_string()),
            ..Default::default()
        };
        Custom::insert(new_custom)
            .exec(db)
            .await
            .expect("failed to write custom to database");
    }
    true
}

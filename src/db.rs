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
            name: Set(ip.name.to_string()),
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

// Get database mac_id asociated with Mac hardware address.
pub(crate) async fn record_activity(
    database_url: &str,
    interface: &str,
    mac_id: i32,
    ip_id: i32,
) -> Option<i32> {
    let new_activity = recent_activity::ActiveModel {
        // @TODO: On SQLite this is apparently a string?
        //timestamp: Set(chrono::Utc::now().naive_utc().to_owned()),
        timestamp: Set(chrono::Utc::now().naive_utc().to_string()),
        interface: Set(interface.to_string()),
        mac_id: Set(mac_id),
        ip_id: Set(ip_id),
        ..Default::default()
    };

    let new_activity_id = {
        let db = connection(database_url).await;
        RecentActivity::insert(new_activity)
            .exec(db)
            .await
            .expect("failed to write activity to database")
    };
    Some(new_activity_id.last_insert_id)
}

// Thread auditing recent mac activity.

use chrono::{naive::NaiveDateTime, Days, Utc};
use sea_orm::*;
use serde::Serialize;

use netgrasp_entity::{prelude::*, *};

use crate::sea_query::Expr;
use crate::{db, utils, Config, CustomActiveFilter, MINUTES_ACTIVE_FOR};

// Send a simple messsage to Slack.
#[derive(Debug, Serialize)]
struct SlackMessage {
    channel: String,
    text: String,
}

// Audit thread analyzes recent_activity.
pub async fn audit_loop(database_url: String, config: &Config) {
    let mut every_second = 0;
    let mut every_minute = 0;

    let custom_active_filters = utils::get_custom_active_filters(&config);

    loop {
        // Every second...
        if utils::timestamp_now() - every_second > 1 {
            let db = db::connection(&database_url).await;
            every_second = utils::timestamp_now();

            // Retrieve each unaudited Mac hardware address.
            let recent_activity = match recent_activity::Entity::find()
                .filter(recent_activity::Column::Audited.eq(0))
                .group_by(recent_activity::Column::Interface)
                .group_by(recent_activity::Column::Mac)
                .all(db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("audit recent_activity query error: {}", e);
                    Vec::new()
                }
            };

            for activity in recent_activity {
                // Determine when this Mac was last seen.
                let seen_mac = match recent_activity::Entity::find()
                    .filter(recent_activity::Column::Audited.eq(1))
                    .filter(recent_activity::Column::Mac.contains(&activity.mac))
                    .order_by_desc(recent_activity::Column::Timestamp)
                    .one(db)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("audit recent_activity query error: {}", e);
                        None
                    }
                };

                let minutes_active_for =
                    get_minutes_active_for(&activity.custom, &custom_active_filters);
                let recent_activity = was_recently_active(seen_mac, minutes_active_for);

                // @TODO: Add generic notification library/integration(s) here.
                if !recent_activity {
                    let mac_stats = db::get_mac_stats(&database_url, &activity.mac).await;

                    println!("Newly active: {:#?}", activity);
                    // @TODO: For now, hard code a simple Slack notification.
                    if let (Some(slack_channel), Some(slack_webhook)) =
                        (config.slack_channel.as_ref(), config.slack_webhook.as_ref())
                    {
                        let mut text = vec![];
                        if mac_stats.is_some() {
                            text.push("Device returned:".to_string());
                        } else {
                            text.push("New device:".to_string());
                        }
                        if let Some(custom) = activity.custom {
                            text.push(format!(" - Custom: {}", custom));
                        }
                        if let Some(host) = activity.host {
                            text.push(format!(" - Host: {}", host));
                        }
                        text.push(format!(" - IP: {}", activity.ip));
                        if let Some(vendor) = activity.vendor {
                            text.push(format!(" - Vendor: {}", vendor));
                        }
                        text.push(format!(" - MAC: {}", activity.mac));
                        if let Some(stats) = mac_stats {
                            if let Some(recent) = stats.seen_recently {
                                text.push(format!(
                                    " - Last seen: {}",
                                    utils::time_ago(recent, false)
                                ));
                                text.push(format!(" - Times seen recently: {}", stats.seen_count));
                            }
                            text.push(format!(
                                " - First seen: {}",
                                utils::time_ago(stats.seen_first, false)
                            ));
                        }

                        let message = SlackMessage {
                            channel: slack_channel.to_string(),
                            text: text.join("\n"),
                        };
                        let client = reqwest::Client::new();
                        let _res = client.post(slack_webhook).json(&message).send().await;
                    }
                }

                // Update database, activity has been audited.
                match RecentActivity::update_many()
                    .col_expr(recent_activity::Column::Audited, Expr::value(1))
                    .filter(recent_activity::Column::Mac.contains(&activity.mac))
                    .filter(recent_activity::Column::Audited.eq(0))
                    .exec(db)
                    .await
                {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("update recent_activity fatal error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }

        // Every minute...
        if utils::timestamp_now() - every_minute > 60 {
            let db = db::connection(&database_url).await;
            every_minute = utils::timestamp_now();

            let three_days = chrono::Utc::now()
                .naive_utc()
                .checked_sub_days(Days::new(3))
                .unwrap()
                .to_string();

            let _res = match recent_activity::Entity::delete_many()
                .filter(recent_activity::Column::Timestamp.lt(three_days))
                .exec(db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("fatal database error: {}", e);
                    std::process::exit(1);
                }
            };
            //println!("deleted {:?} rows from recent_activity table.", res);
        }

        // Loop 4 times per second.
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
}

fn get_minutes_active_for(
    custom_name: &Option<String>,
    custom_active_filters: &Vec<CustomActiveFilter>,
) -> u32 {
    if let Some(custom) = custom_name {
        for filter in custom_active_filters {
            if filter.0.contains(custom) {
                return filter.1;
            }
        }
    }
    MINUTES_ACTIVE_FOR
}

fn was_recently_active(seen_mac: Option<recent_activity::Model>, minutes_active_for: u32) -> bool {
    if let Some(seen) = seen_mac {
        // Convert timestamp to NaiveDateTime.
        let last_seen = match NaiveDateTime::parse_from_str(&seen.timestamp, "%Y-%m-%d %H:%M:%S.%f")
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("failed to parse timestamp: {}", e);
                return false;
            }
        };

        let now = Utc::now().naive_utc();
        let diff = now - last_seen;
        if diff.num_minutes() < minutes_active_for as i64 {
            return true;
        }
    }
    false
}

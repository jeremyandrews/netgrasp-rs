// Thread auditing recent mac activity.

use chrono::{Days, Duration};
use sea_orm::*;
use serde::Serialize;

use netgrasp_entity::{prelude::*, *};

use crate::sea_query::Expr;
use crate::{db, utils, Config};

// Send a simple messsage to Slack.
#[derive(Debug, Serialize)]
struct SlackMessage {
    channel: String,
    text: String,
}

#[derive(FromQueryResult, Debug)]
pub struct DeviceSeen {
    seen_count: i32,
    seen_recently: Option<String>,
    seen_first: String,
}

// Audit thread analyzes recent_activity.
pub async fn audit_loop(database_url: String, config: &Config) {
    let mut every_second = 0;
    let mut every_minute = 0;
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

            let active_duration = Duration::minutes(crate::MINUTES_ACTIVE_FOR);
            for activity in recent_activity {
                let active_timestamp = chrono::Utc::now()
                    .naive_utc()
                    .checked_sub_signed(active_duration)
                    .unwrap()
                    .to_string();
                // Determine if this Mac has been seen within the past 2.5 hours.
                let seen_mac = match recent_activity::Entity::find()
                    .filter(recent_activity::Column::Audited.eq(1))
                    .filter(recent_activity::Column::Mac.contains(&activity.mac))
                    .filter(recent_activity::Column::Timestamp.gt(active_timestamp))
                    .one(db)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("audit recent_activity query error: {}", e);
                        None
                    }
                };

                // @TODO: Add generic notification library/integration(s) here.
                if seen_mac.is_none() {
                    let timestamp = recent_activity::Entity::find()
                        .left_join(Mac)
                        .filter(recent_activity::Column::Mac.contains(&activity.mac))
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
                        .expect("failed to poll timestamp information");

                    println!("Newly active: {:#?}", activity);
                    // @TODO: For now, hard code a simple Slack notification.
                    if let (Some(slack_channel), Some(slack_webhook)) =
                        (config.slack_channel.as_ref(), config.slack_webhook.as_ref())
                    {
                        let mut text = vec![];
                        if timestamp.is_some() {
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
                        if let Some(seen) = timestamp {
                            if let Some(recent) = seen.seen_recently {
                                text.push(format!(
                                    " - Last seen: {}",
                                    utils::time_ago(recent, false)
                                ));
                                text.push(format!(" - Times seen recently: {}", seen.seen_count));
                            }
                            text.push(format!(
                                " - First seen: {}",
                                utils::time_ago(seen.seen_first, false)
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

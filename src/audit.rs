// Thread auditing recent mac activity.

use chrono::Days;
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

            for activity in recent_activity {
                // Determine if this Mac has been seen recently.
                let seen_mac = match recent_activity::Entity::find()
                    .filter(recent_activity::Column::Audited.eq(1))
                    .filter(recent_activity::Column::Mac.contains(&activity.mac))
                    .one(db)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("audit recent_activity query error: {}", e);
                        None
                    }
                };

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

                // @TODO: Add generic notification library/integration(s) here.
                if seen_mac.is_none() {
                    println!("Seen for the first time: {:#?}", activity);
                    // @TODO: For now, hard code a simple Slack notification.
                    if let (Some(slack_channel), Some(slack_webhook)) =
                        (config.slack_channel.as_ref(), config.slack_webhook.as_ref())
                    {
                        let message = SlackMessage {
                            channel: slack_channel.to_string(),
                            text: format!("New device:\n - Custom: {:?}\n - Host: {:?}\n - IP: {}\n - Vendor: {:?}\n - Mac: {}",
                            activity.custom,
                            activity.host,
                            activity.ip,
                            activity.vendor,
                            activity.mac,
                        )};
                        let client = reqwest::Client::new();
                        let _res = client.post(slack_webhook).json(&message).send().await;
                    }
                }
            }
        }

        // Every minute...
        if utils::timestamp_now() - every_minute > 60 {
            let db = db::connection(&database_url).await;
            every_minute = utils::timestamp_now();

            // @TODO: Shrink this to 2-3 hours.
            let yesterday = chrono::Utc::now()
                .naive_utc()
                .checked_sub_days(Days::new(1))
                .unwrap()
                .to_string();

            let _res = match recent_activity::Entity::delete_many()
                .filter(recent_activity::Column::Timestamp.lt(yesterday))
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

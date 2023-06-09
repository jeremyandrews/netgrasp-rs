use async_once_cell::OnceCell;
use sea_orm::*;

static DB: OnceCell<DatabaseConnection> = OnceCell::new();

pub(crate) async fn connection(database_url: &str) -> &DatabaseConnection {
    DB
        .get_or_init(async {
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
pub use sea_orm_migration::prelude::*;

mod m20230608_052146_mac;
mod m20230608_083623_ip;
mod m20230608_084816_recent_activity;
mod m20230608_084829_activity_log;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230608_052146_mac::Migration),
            Box::new(m20230608_083623_ip::Migration),
            Box::new(m20230608_084816_recent_activity::Migration),
            Box::new(m20230608_084829_activity_log::Migration),
        ]
    }
}

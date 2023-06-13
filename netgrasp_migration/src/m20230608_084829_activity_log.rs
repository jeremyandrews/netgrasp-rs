use sea_orm_migration::prelude::*;

use super::m20230608_052146_mac::Mac;
use super::m20230608_083623_ip::Ip;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ActivityLog::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ActivityLog::ActivityLogId)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ActivityLog::Timestamp)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ActivityLog::Interface).string().not_null())
                    .col(ColumnDef::new(ActivityLog::MacId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-mac-macid")
                            .from(ActivityLog::Table, ActivityLog::MacId)
                            .to(Mac::Table, Mac::MacId),
                    )
                    .col(ColumnDef::new(ActivityLog::IpId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ip-ipid")
                            .from(ActivityLog::Table, ActivityLog::IpId)
                            .to(Ip::Table, Ip::IpId),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ActivityLog::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum ActivityLog {
    Table,
    ActivityLogId,
    Timestamp,
    Interface,
    MacId,
    IpId,
}

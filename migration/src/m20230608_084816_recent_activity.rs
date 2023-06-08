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
                    .table(RecentActivity::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RecentActivity::RecentActivityId)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RecentActivity::Timestamp)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RecentActivity::Interface).string().not_null())
                    .col(
                        ColumnDef::new(RecentActivity::MacId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-mac-macid")
                            .from(RecentActivity::Table, RecentActivity::MacId)
                            .to(Mac::Table, Mac::MacId),
                    )
                    .col(
                        ColumnDef::new(RecentActivity::IpId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ip-ipid")
                            .from(RecentActivity::Table, RecentActivity::IpId)
                            .to(Ip::Table, Ip::IpId),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RecentActivity::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum RecentActivity {
    Table,
    RecentActivityId,
    Timestamp,
    Interface,
    MacId,
    IpId,
}

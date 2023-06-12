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
                    .table(Custom::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Custom::CustomId)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Custom::Created).timestamp().not_null())
                    .col(ColumnDef::new(Custom::Updated).timestamp().not_null())
                    .col(ColumnDef::new(Custom::MacId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-mac-macid")
                            .from(Custom::Table, Custom::MacId)
                            .to(Mac::Table, Mac::MacId),
                    )
                    .col(ColumnDef::new(Custom::IpId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ip-ipid")
                            .from(Custom::Table, Custom::IpId)
                            .to(Ip::Table, Ip::IpId),
                    )
                    .col(ColumnDef::new(Custom::Name).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Custom::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum Custom {
    Table,
    CustomId,
    Created,
    Updated,
    MacId,
    IpId,
    Name,
}

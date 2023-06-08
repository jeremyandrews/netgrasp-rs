use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Ip::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Ip::IpId)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Ip::Created).timestamp().not_null())
                    .col(ColumnDef::new(Ip::Updated).timestamp().not_null())
                    .col(ColumnDef::new(Ip::Interface).string().not_null())
                    .col(ColumnDef::new(Ip::Address).string().not_null())
                    .col(ColumnDef::new(Ip::Name).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-ip-interface-address")
                    .unique()
                    .table(Ip::Table)
                    .col(Ip::Interface)
                    .col(Ip::Address)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-ip-name")
                    .table(Ip::Table)
                    .col(Ip::Name)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Ip::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub(crate) enum Ip {
    Table,
    IpId,
    Created,
    Updated,
    Interface,
    Address,
    Name,
}

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Mac::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Mac::MacId)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Mac::Created).timestamp().not_null())
                    .col(ColumnDef::new(Mac::HardwareAddress).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-mac-hardware")
                    .unique()
                    .table(Mac::Table)
                    .col(Mac::HardwareAddress)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Mac::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub(crate) enum Mac {
    Table,
    MacId,
    Created,
    HardwareAddress,
}

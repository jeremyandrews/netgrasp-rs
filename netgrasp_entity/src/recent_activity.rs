//! `SeaORM` Entity. Generated by sea-orm-codegen 0.11.3

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "recent_activity")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub recent_activity_id: i32,
    pub timestamp: String,
    pub interface: String,
    pub mac_id: i32,
    pub mac: String,
    pub vendor: Option<String>,
    pub ip_id: i32,
    pub ip: String,
    pub host: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::ip::Entity",
        from = "Column::IpId",
        to = "super::ip::Column::IpId",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Ip,
    #[sea_orm(
        belongs_to = "super::mac::Entity",
        from = "Column::MacId",
        to = "super::mac::Column::MacId",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Mac,
}

impl Related<super::ip::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Ip.def()
    }
}

impl Related<super::mac::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Mac.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

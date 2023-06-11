//! `SeaORM` Entity. Generated by sea-orm-codegen 0.11.3

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "ip")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub ip_id: i32,
    pub created: String,
    pub updated: String,
    pub interface: String,
    pub address: String,
    pub host: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::activity_log::Entity")]
    ActivityLog,
    #[sea_orm(has_many = "super::custom::Entity")]
    Custom,
    #[sea_orm(has_many = "super::recent_activity::Entity")]
    RecentActivity,
}

impl Related<super::activity_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ActivityLog.def()
    }
}

impl Related<super::custom::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Custom.def()
    }
}

impl Related<super::recent_activity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RecentActivity.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

use super::schema::{interface, ip, mac, network_event, stats, vendor};

#[derive(Debug, Default, Queryable, QueryableByName)]
#[table_name = "network_event"]
pub struct NetworkEvent {
    pub netevent_id: i32,
    pub recent: i32,
    pub processed: i32,
    pub interface_id: i32,
    pub mac_id: i32,
    pub vendor_id: i32,
    pub ip_id: i32,
    pub tgt_mac_id: i32,
    pub tgt_vendor_id: i32,
    pub tgt_ip_id: i32,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable, Debug, Default, Queryable)]
#[table_name = "network_event"]
pub struct NewNetworkEvent {
    pub recent: i32,
    pub processed: i32,
    pub interface_id: i32,
    pub mac_id: i32,
    pub vendor_id: i32,
    pub ip_id: i32,
    pub tgt_mac_id: i32,
    pub tgt_vendor_id: i32,
    pub tgt_ip_id: i32,
    pub created: i32,
    pub updated: i32,
}

#[derive(Debug, Default, Queryable, QueryableByName)]
#[table_name = "interface"]
pub struct Interface {
    pub interface_id: i32,
    pub label: String,
    pub address: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable)]
#[table_name = "interface"]
pub struct NewInterface {
    pub label: String,
    pub address: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Debug, Default, Queryable, QueryableByName)]
#[table_name = "mac"]
pub struct Mac {
    pub mac_id: i32,
    pub is_self: i32,
    pub vendor_id: i32,
    pub address: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable)]
#[table_name = "mac"]
pub struct NewMac {
    pub is_self: i32,
    pub vendor_id: i32,
    pub address: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Debug, Default, Clone, Queryable, QueryableByName, Identifiable)]
#[primary_key(ip_id)]
#[table_name = "ip"]
pub struct Ip {
    pub ip_id: i32,
    pub mac_id: i32,
    pub address: String,
    pub host_name: String,
    pub custom_name: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable)]
#[table_name = "ip"]
pub struct NewIp {
    pub mac_id: i32,
    pub address: String,
    pub host_name: String,
    pub custom_name: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Debug, Default, Queryable, QueryableByName)]
#[table_name = "stats"]
pub struct Stats {
    pub stats_id: i32,
    pub mac_id: i32,
    pub ip_id: i32,
    pub period_date: i32,
    pub period_length: i32,
    pub period_number: i32,
    pub total: i32,
    pub different: i32,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable)]
#[table_name = "stats"]
pub struct NewStats {
    pub mac_id: i32,
    pub ip_id: i32,
    pub period_date: i32,
    pub period_length: i32,
    pub period_number: i32,
    pub total: i32,
    pub different: i32,
    pub created: i32,
    pub updated: i32,
}

#[derive(Debug, Default, Queryable, QueryableByName)]
#[table_name = "vendor"]
pub struct Vendor {
    pub vendor_id: i32,
    pub name: String,
    pub full_name: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable)]
#[table_name = "vendor"]
pub struct NewVendor {
    pub name: String,
    pub full_name: String,
    pub created: i32,
    pub updated: i32,
}

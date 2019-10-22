//use super::schema::{arp, ip, mac, vendor, event};
use super::schema::{arp, ip, mac, vendor};

/*
#[derive(Queryable, Debug)]
pub struct Arp {
    pub arp_id: i32,
    pub src_mac_id: i32,
    pub src_ip_id: i32,
    pub src_vendor_id: i32,
    pub tgt_ip_id: i32,
    pub interface: String,
    pub host_name: String,
    pub custom_name: String,
    pub vendor_name: String,
    pub vendor_full_name: String,
    pub src_mac: String,
    pub src_ip: String,
    pub tgt_mac: String,
    pub tgt_ip: String,
    pub operation: i32,
    pub is_self: i32,
    pub is_active: i32,
    pub processed: i32,
    pub matched: i32,
    pub event_type: String,
    pub event_description: String,
    pub created: i32,
    pub updated: i32,
}
*/

#[derive(Insertable)]
#[table_name = "arp"]
pub struct NewArp {
    pub src_mac_id: i32,
    pub src_ip_id: i32,
    pub src_vendor_id: i32,
    pub tgt_ip_id: i32,
    pub interface: String,
    pub host_name: String,
    pub custom_name: String,
    pub vendor_name: String,
    pub vendor_full_name: String,
    pub src_mac: String,
    pub src_ip: String,
    pub tgt_mac: String,
    pub tgt_ip: String,
    pub operation: i32,
    pub is_self: i32,
    pub is_active: i32,
    pub processed: i32,
    pub matched: i32,
    pub event_type: String,
    pub event_description: String,
    pub created: i32,
    pub updated: i32,
}

#[derive(Queryable, Debug)]
pub struct Mac {
    pub mac_id: i32,
    pub vendor_id: i32,
    pub address: String,
    pub is_self: i32,
    pub created: i32,
    pub updated: i32,
}

#[derive(Insertable)]
#[table_name = "mac"]
pub struct NewMac {
    pub vendor_id: i32,
    pub address: String,
    pub is_self: i32,
    pub created: i32,
    pub updated: i32,
}

#[derive(Queryable, QueryableByName, Debug)]
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

#[derive(Queryable, Default, Debug)]
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

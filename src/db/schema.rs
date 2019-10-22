table! {
    arp (arp_id) {
        arp_id -> Integer,
        src_mac_id -> Integer,
        src_ip_id -> Integer,
        src_vendor_id -> Integer,
        tgt_ip_id -> Integer,
        interface -> Text,
        host_name -> Text,
        custom_name -> Text,
        vendor_name -> Text,
        vendor_full_name -> Text,
        src_mac -> Text,
        src_ip -> Text,
        tgt_mac -> Text,
        tgt_ip -> Text,
        operation -> Integer,
        is_self -> Integer,
        is_active -> Integer,
        processed -> Integer,
        matched -> Integer,
        event_type -> Text,
        event_description -> Text,
        created -> Integer,
        updated -> Integer,
    }
}

table! {
    ip (ip_id) {
        ip_id -> Integer,
        mac_id -> Integer,
        address -> Text,
        host_name -> Text,
        custom_name -> Text,
        created -> Integer,
        updated -> Integer,
    }
}

table! {
    mac (mac_id) {
        mac_id -> Integer,
        vendor_id -> Integer,
        address -> Text,
        is_self -> Integer,
        created -> Integer,
        updated -> Integer,
    }
}

table! {
    vendor (vendor_id) {
        vendor_id -> Integer,
        name -> Text,
        full_name -> Text,
        created -> Integer,
        updated -> Integer,
    }
}

allow_tables_to_appear_in_same_query!(
    arp,
    ip,
    mac,
    vendor,
);

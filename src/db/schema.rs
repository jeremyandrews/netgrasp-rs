table! {
    interface (interface_id) {
        interface_id -> Integer,
        label -> Text,
        address -> Text,
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
        is_self -> Integer,
        vendor_id -> Integer,
        address -> Text,
        created -> Integer,
        updated -> Integer,
    }
}

table! {
    network_event (netevent_id) {
        netevent_id -> Integer,
        recent -> Integer,
        processed -> Integer,
        interface_id -> Integer,
        mac_id -> Integer,
        vendor_id -> Integer,
        ip_id -> Integer,
        tgt_mac_id -> Integer,
        tgt_vendor_id -> Integer,
        tgt_ip_id -> Integer,
        created -> Integer,
        updated -> Integer,
    }
}

table! {
    stats (stats_id) {
        stats_id -> Integer,
        mac_id -> Integer,
        ip_id -> Integer,
        period_date -> Integer,
        period_length -> Integer,
        period_number -> Integer,
        total -> Integer,
        different -> Integer,
        mean -> Float,
        median -> Float,
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

joinable!(ip -> mac (mac_id));
joinable!(mac -> vendor (vendor_id));
joinable!(network_event -> interface (interface_id));
joinable!(network_event -> ip (ip_id));
joinable!(network_event -> mac (mac_id));
joinable!(network_event -> vendor (vendor_id));

allow_tables_to_appear_in_same_query!(
    interface,
    ip,
    mac,
    network_event,
    stats,
    vendor,
);

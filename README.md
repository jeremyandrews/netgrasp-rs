# Netgrasp

A passive network observation tool.

Rewriting Netgrasp in Rust.
<https://github.com/jeremyandrews/netgrasp>

## Details

* Leverages [smoltcp](https://lib.rs/crates/smoltcp) to monitor a network interface for ARP packets.
* Leverages [clap](https://lib.rs/crates/clap) to provide command line argument parsing.
* Leverages [simplelog](https://lib.rs/crates/simplelog) to provide logging to stdout and files.
* Leverages [get_if_addrs](https://lib.rs/crates/get_if_addrs) to validate network interfaces.
* Leverages [sqlite](https://crates.io/crates/sqlite) to integrate with Sqlite3.
* Leverages [dns-lookup](https://crates.io/crates/dns-lookup/) to perform reverse DNS lookups.
* Leverages [oui](https://crates.io/crates/oui) to perform vendor lookups of MAC addresses.
* Leverages [reqwest](https://crates.io/crates/reqwest) to automatically download Wireshark OUI database.

## TODO

1. Parse configuration file
    * support multiple configuration paths
    * allow CLI override of configuration path
    * catch HUP signal and reload configuration
    * use TOML like rust (<https://crates.io/crates/toml)>
1. Daemonize (<https://github.com/knsd/daemonize)>
    * drop permissions where unnecessary
1. Log/process events
1. Notifications (email, other?)
    * to review (<https://crates.io/crates/mailstrom>)
    * to review (<https://crates.io/crates/lettre_email>)
    * to review (<https://crates.io/crates/mail>)
    * to review (<https://crates.io/crates/notify-rust>)
1. Support graceful shutdown
1. Support monitoring multiple interfaces at the same time
1. Don't panic on failures, handle gracefully
    * handle the ethernet interface going away (gracefully shutdown? or sleep and retry?)
    * handle bad packets
    * handle SQL errors
1. Implement tests
1. Expose data and control through API

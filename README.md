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

## TODO

1. Get MAC vendors
    * an option, but doesn't seem to update the data source <https://github.com/flier/rust-manuf>
    * looks like a better option <https://github.com/meh/rust-hwaddr>
    * or do it like netgrasp-py, and query this API: 
1. Parse configuration file
    * support multiple configuration paths
    * allow CLI override of configuration path
    * catch HUP signal and reload configuration
    * use TOML like rust (<https://crates.io/crates/toml)>
1. Daemonize (<https://github.com/knsd/daemonize)>
1. Notifications (email, other?)
1. Support graceful shutdown
1. Support monitoring multiple interfaces at the same time
1. Expose data and control through API

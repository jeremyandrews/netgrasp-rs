# Netgrasp

A passive network observation tool.

Rewriting Netgrasp in Rust.
<https://github.com/jeremyandrews/netgrasp>

## Details

* Leverages [smoltcp](https://lib.rs/crates/smoltcp) to monitor a network interface for ARP packets.
* Leverages [clap](https://lib.rs/crates/clap) to provide command line argument parsing.
* Leverages [simplelog](https://lib.rs/crates/simplelog) to provide logging to stdout and files.
* Leverages [get_if_addrs](https://lib.rs/crates/get_if_addrs) to validate network interface.
* Leverages [sqlite](https://github.com/stainless-steel/sqlite) to integrate with Sqlite3.

## TODO

1. Integrate SQLite backend
    * Select a crate:
    * <https://github.com/stainless-steel/sqlite>
    * <https://github.com/jgallagher/rusqlite>
        * <https://rust-lang-nursery.github.io/rust-cookbook/database/sqlite.html>
        * Recipe doesn't work in my testing
        * Library examples don't work in my testing
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
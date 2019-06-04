# Netgrasp

A passive network observation tool.

Rewriting Netgrasp in Rust.
<https://github.com/jeremyandrews/netgrasp>

## Setup

Temporarily, must manually download `manuf.txt` which is used by `oui` for MAC lookup:

    wget -O manuf.txt 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'
    mkdir data/
    mv manuf.txt data/

@TODO: automate download and installation of `manuf.txt`, and provide a way to keep it up-to-date.

## Details

* Leverages [smoltcp](https://lib.rs/crates/smoltcp) to monitor a network interface for ARP packets.
* Leverages [clap](https://lib.rs/crates/clap) to provide command line argument parsing.
* Leverages [simplelog](https://lib.rs/crates/simplelog) to provide logging to stdout and files.
* Leverages [get_if_addrs](https://lib.rs/crates/get_if_addrs) to validate network interfaces.
* Leverages [sqlite](https://crates.io/crates/sqlite) to integrate with Sqlite3.
* Leverages [dns-lookup](https://crates.io/crates/dns-lookup/) to perform reverse DNS lookups.
* Leverages [oui](https://crates.io/crates/oui) to perform vendor lookups of MAC addresses.

## TODO

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

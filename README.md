# Netgrasp

A passive network observation tool.

## Overview

Netgrasp monitors Arp traffic, performing MAC and reverse-DNS lookups to detect devices.

* Leverages [arp-toolkit](https://crates.io/crates/arp-toolkit) to monitor network interfaces for ARP packets.
* Leverages [clap](https://crates.io/crates/clap) and [figment](https://crates.io/crates/figment) to provide flexible configuration.
* Leverages [dns-lookup](https://crates.io/crates/dns-lookup/) to perform reverse DNS lookups.
* Leverages [if_addrs](https://crates.io/crates/if_addrs) to validate network interfaces.
* Leverages [mac_oui](https://crates.io/crates/mac_oui) to perform vendor lookups of MAC addresses.


* Leverages [simplelog](https://lib.rs/crates/simplelog) to provide logging to stdout and files.

## Notes

Create database:
    ```
    DATABASE_URL="sqlite://netgrasp.db" sea-orm-cli migrate fresh
    ```

Update entities:
    ```
    DATABASE_URL="sqlite://netgrasp.db" sea-orm-cli generate entity -o netgrasp_entity/src
    ```

## TODO

1. Parse configuration file
    * catch HUP signal and reload configuration
1. Daemonize (<https://github.com/knsd/daemonize)>
    * drop permissions where unnecessary
1. Support graceful shutdown
1. Implement tests
1. Expose data and control through API

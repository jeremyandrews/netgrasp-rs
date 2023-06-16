# Netgrasp

A passive network observation tool.

## Overview

Netgrasp monitors and records Arp traffic. Lookups are performed to attempt to determine the Vendor of the MAC, the IP assigned to the MAC, and the hostname assigned to the IP. Custom labels can also be applied.

Active devices on the network are displayed on the CLI. Notifications of new or returning devices can be sent to Slack.

* Leverages [arp-toolkit](https://crates.io/crates/arp-toolkit) to monitor network interfaces for ARP packets.
* Leverages [clap](https://crates.io/crates/clap) and [figment](https://crates.io/crates/figment) to provide flexible configuration.
* Leverages [dns-lookup](https://crates.io/crates/dns-lookup/) to perform reverse DNS lookups.
* Leverages [if_addrs](https://crates.io/crates/if_addrs) to validate network interfaces.
* Leverages [mac_oui](https://crates.io/crates/mac_oui) to perform vendor lookups of MAC addresses.

## Using Netgrasp

### Configuration:

It is recommended that you copy the example toml file and then configure appropriately:
```
cp netgrasp.toml.example netgrasp.toml
```

 - `interfaces` must be configured to include one or more interfaces to listen to arp traffic
 - `database` defaults to `netgrasp.db` in the directory netgrasp is run from
 - `slack_channel` and `slack_webhook` should only be configured if you'd like to receive real-time slack notifications of new or returning devices on your network

### Database:

Currently the database must be created manually with the following steps, run from the netgrasp development directory. Replace `netgrasp.db` with your desired database path and name:
```
touch netgraspdb
DATABASE_URL="sqlite://netgrasp.db" sea-orm-cli migrate -d netgrasp_migration fresh
```

### Running:

Netgrasp can be launched with `cargo`, or pre-built and manually installed (for example in `/usr/local/bin`).

Launching from cargo:
`cargo run --release`

Building and installing:
```
cargo build --release
sudo cp target/release/netgrasp /usr/local/bin
```

### Custom names

To apply a custom name to devices detected on your network, launch netgrasp with the `--identify` flag. You can do this while the main daemon is running and actively monitoring the network.
`cargo run --release -- --identify`

This will loop through all recently active devices displaying what information is known, and allow you to optionally identify the device with a custom name. Type a custom name and press return to assign a custom name. Press return without typing anything to skip.

By default, netgrasp will only loop through devices that have not yet been identified. To edit the custom name for devices already identified, use the `--reidentify` flag.
`cargo run --release -- --reidentify`

### Filters

It is possible to hide devices using case-insensitive pattern matching on the custom name. For example, to hide all devices that you've identified with a custom name that includes the phrases "access point" or "switch" configure as follows:
`cargo run --release -- --custom-hide-filters="access point,switch"`

By default, Netgrasp assumes a decide is active for 150 minutes (2.5 hours) after it was last seen. It is possible to configure a custom active time in minutes using case-insensitive pattern matching on the custom name. For example:
`cargo run --release -- --custom-active-filters="phone|45,switch|1440"`

## Development Notes

Create new table:
`sea-orm-cli migrate generate <TableName>`

Recreate database:
`DATABASE_URL="sqlite://netgrasp.db" sea-orm-cli migrate -d netgrasp_migration fresh`

Update entities:
`DATABASE_URL="sqlite://netgrasp.db" sea-orm-cli generate entity --with-serde serialize -o netgrasp_entity/src`

## TODO

1. Add filters to --identify and --reidentify
1. Automate database creation and migrations
1. Implement tests
1. Parse configuration file
    * catch HUP signal and reload configuration
    * fix figment implementation to set config in the following priority:
      # TOML Configuration
      # environment variable
      # command line option
    * expose more functionality to configuration
1. Daemonize (<https://github.com/knsd/daemonize)>
1. Support graceful shutdown
1. Expose data and control through API

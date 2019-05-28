# Netgrasp

Rewriting Netgrasp in Rust.
https://github.com/jeremyandrews/netgrasp

## Dependencies

* none

## TODO

### Compare smoltcp to pcap

* still maintained: https://github.com/m-labs/smoltcp
* authors/maintainers: https://m-labs.hk/
* has simple ARP listening support, for example: `cargo build --example tcpdump`
* much smaller dependency chain
* does it support Mac OS X?
* does it support FreeBSD?
* does it support Windows? (And, do I care?)

### Select a configuration crate

* currently using config-rs
* https://github.com/mehcode/config-rs
* maintainer not happy with current design: https://github.com/mehcode/config-rs/issues/111
* supports hjson which I like

1. Parse configuration file (with HUP support for reloading)
    * support multiple configuration paths
    * allow CLI override of configuration path
    * either support HUP signal, or watch (https://github.com/mehcode/config-rs/tree/master/examples/watch)
1. Create multiple threads for: parent, listening for ARPs, exposing API
1. Daemonize
1. Listen for ARP packets on one or more interfaces
1. Integrate SQLite backend
1. Handle CLI interactions
1. Notifications (email, other?)
1. Expose data and control through API
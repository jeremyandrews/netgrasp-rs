# Netgrasp

Rewriting Netgrasp in Rust.
https://github.com/jeremyandrews/netgrasp

## Dependencies

In order to build Netgrasp, the following libraries (or their equivalent) need to be installed manually (these dependencies are not managed by Cargo):

* libpcap-devel

## TODO

Compare smoltcp to pcap
 * still maintained: https://github.com/m-labs/smoltcp
 * authors/maintainers: https://m-labs.hk/
 * has simple ARP listening support, for example: `cargo build --example tcpdump`
 * much smaller dependency chain
 * does it support Mac OS X?
 * does it support Windows? (And, do I care?)

1. Parse configuration file (with HUP support for reloading)
1. Create multiple threads for: parent, listening for ARPs, exposing API
1. Daemonize
1. Listen for ARP packets on one or more interfaces
1. Integrate SQLite backend
1. Handle CLI interactions
1. Notifications (email, other?)
1. Expose data and control through API
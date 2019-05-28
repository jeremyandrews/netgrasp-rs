// https://lib.rs/crates/smoltcp
extern crate smoltcp;

// https://docs.rs/clap/
extern crate clap;

use clap::{Arg, App};
// https://doc.rust-lang.org/std/os/unix/io/trait.AsRawFd.html
// (This is supported only on UNIX; Windows would use AsRawSocket instead.)
use std::os::unix::io::AsRawFd;
// https://github.com/m-labs/smoltcp/blob/master/src/phy/sys/mod.rs#L26
use smoltcp::phy::wait as phy_wait;
// Device: https://github.com/m-labs/smoltcp/blob/master/src/phy/raw_socket.rs#L40
// RxToken: https://github.com/m-labs/smoltcp/blob/master/src/phy/raw_socket.rs#L75
// RawSocket: https://github.com/m-labs/smoltcp/blob/master/src/phy/raw_socket.rs#L24
use smoltcp::phy::{Device, RxToken, RawSocket};
// PrettyPrinter: https://github.com/m-labs/smoltcp/blob/master/src/wire/pretty_print.rs#L96
// EthernetFrame:
//   - "A read/write wrapper around an Ethernet II frame buffer."
//   - https://github.com/m-labs/smoltcp/blob/master/src/wire/ethernet.rs#L79
//   - https://docs.rs/smoltcp/0.5.0/smoltcp/wire/struct.EthernetFrame.html
use smoltcp::wire::{PrettyPrinter, EthernetFrame, EthernetProtocol};
// https://github.com/m-labs/smoltcp/blob/master/src/time.rs#L29
use smoltcp::time::Instant;


// Listening for ARP packets derived from the smoltcp tcpdump example.
// https://github.com/m-labs/smoltcp/blob/master/examples/tcpdump.rs
fn main() {
    // Using clap to parse and validate command line arguments. https://docs.rs/clap/
    let matches = App::new("Netgrasp")
        .version("0.10.0")
        .author("Jeremy Andrews <jeremy@tag1consulting.com>")
        .about("A passive network observation tool")
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Specify a network interface to listen on")
            .required(true)
            .takes_value(true))
        // @TODO: make use of verbosity level
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .get_matches();
    
    // We require an interface so unwrap() is safe here.
    let interface = matches.value_of("interface").unwrap();

    // https://github.com/m-labs/smoltcp/blob/master/src/phy/raw_socket.rs#L24
    // Creates a raw socket, bound to the interface as named in `interface`.
    // Note: this requires superuser privileges, or corresponding capability bit.
    // Passes ifname as a reference.
    let mut socket = RawSocket::new(interface.as_ref()).unwrap();
    // https://doc.rust-lang.org/std/keyword.loop.html
    // Loop until break or exit ...
    loop {
        // https://github.com/m-labs/smoltcp/blob/master/src/phy/sys/mod.rs#L26
        // https://doc.rust-lang.org/std/os/unix/io/trait.AsRawFd.html#tymethod.as_raw_fd
        // Wait forever for socket raw file descriptor to become readable.
        phy_wait(socket.as_raw_fd(), None).unwrap();
        // https://github.com/m-labs/smoltcp/blob/master/src/phy/raw_socket.rs#L51
        // Returns both rx and tx as option, we only use the former.
        let (rx_token, _) = socket.receive().unwrap();
        // https://github.com/m-labs/smoltcp/blob/master/src/phy/raw_socket.rs#L81
        // Consume function is defined in RxToken taking two parameters
        // https://github.com/m-labs/smoltcp/blob/master/src/time.rs
        // Instant::now() is absolute time formatted timestamp [std::time::SystemTime::now]
        // https://doc.rust-lang.org/std/time/struct.SystemTime.html
        // Implemented as a Closure
        // https://doc.rust-lang.org/book/ch13-01-closures.html#refactoring-with-closures-to-store-code
        // More detail on closures:
        // https://stevedonovan.github.io/rustifications/2018/08/18/rust-closures-are-hard.html
        rx_token.consume(Instant::now(), |buffer| {
            // https://docs.rs/smoltcp/0.5.0/smoltcp/wire/struct.EthernetFrame.html#method.new_checked
            // Be sure we have a valid ethernet frame.
            let frame = EthernetFrame::new_checked(&buffer);
            // https://docs.rs/smoltcp/0.5.0/smoltcp/wire/struct.EthernetFrame.html#method.ethertype
            // Determine what type of packet we've received.
            if EthernetFrame::ethertype(&frame.unwrap()) == EthernetProtocol::Arp {
                // The `pretty_print` module provides bits and pieces for printing concise, easily human
                // readable packet listings.
                println!("{}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
            }
            // https://doc.rust-lang.org/std/result/enum.Result.html#variant.Ok
            // Exits closure with success value
            Ok(())
        // https://doc.rust-lang.org/std/result/enum.Result.html#method.unwrap
        // Silences a compiler warning that we don't handle Err(), expecting only an Ok().
        }).unwrap();
    }
}

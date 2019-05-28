// https://lib.rs/crates/smoltcp
extern crate smoltcp;

// https://docs.rs/clap/
extern crate clap;
#[macro_use]
extern crate log;
// https://docs.rs/simplelog/
extern crate simplelog;

use clap::{Arg, App};
use simplelog::*;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::{Device, RxToken, RawSocket};
use smoltcp::wire::{PrettyPrinter, EthernetFrame, EthernetProtocol};
use smoltcp::time::Instant;


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
            .help("Specify the network interface to listen on")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("logfile")
            .short("l")
            .long("logfile")
            .value_name("LOGFILE")
            .help("Path of logfile (default './netgrasp.log')")
            .takes_value(true))
        .arg(Arg::with_name("g")
            .short("g")
            .multiple(true)
            .help("Sets the logged level of verbosity"))
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the output level of verbosity"))
        .get_matches();

    // Allow optionally controlling debug output level
    let debug_level;
    match matches.occurrences_of("v") {
        0 => debug_level = LevelFilter::Warn,
        1 => debug_level = LevelFilter::Info,
        2 => debug_level = LevelFilter::Debug,
        3 | _ => debug_level = LevelFilter::Trace,
    }

    let log_level;
    match matches.occurrences_of("g") {
        0 => log_level = LevelFilter::Warn,
        1 => log_level = LevelFilter::Info,
        2 => log_level = LevelFilter::Debug,
        3 | _ => log_level = LevelFilter::Trace,
    }

    // @TODO: confirm that the path exists and is writeable
    let log_file = matches.value_of("logfile").unwrap_or("./netgrasp.log");
    
    CombinedLogger::init(
        vec![
            TermLogger::new(debug_level, Config::default()).unwrap(),
            WriteLogger::new(log_level, Config::default(), File::create(log_file).unwrap()),
        ]
    ).unwrap();
    info!("Output verbosity level: {}", debug_level);
    info!("Logfile verbosity level: {}", log_level);

    info!("Writing to log file: {}", log_file);

    // We require an interface so unwrap() is safe here.
    let interface = matches.value_of("interface").unwrap();
    info!("Listening interface: {}", interface);

    // Creates a raw socket, bound to the interface as named in `interface`.
    // Note: this requires superuser privileges, or corresponding capability bit.
    // Passes ifname as a reference.
    let mut socket = RawSocket::new(interface.as_ref()).unwrap();
    loop {
        // Logic for listening to ARP packets with smoltcp derived from tcpdump example:
        //   https://github.com/m-labs/smoltcp/blob/master/examples/tcpdump.rs
        // Wait forever for socket raw file descriptor to become readable.
        phy_wait(socket.as_raw_fd(), None).unwrap();
        // Returns both rx and tx as option, we only use the former.
        let (rx_token, _) = socket.receive().unwrap();
        // Implemented as a Closure:
        //   https://doc.rust-lang.org/book/ch13-01-closures.html#refactoring-with-closures-to-store-code
        // More detail on closures:
        //   https://stevedonovan.github.io/rustifications/2018/08/18/rust-closures-are-hard.html
        rx_token.consume(Instant::now(), |buffer| {
            // Be sure we have a valid ethernet frame.
            let frame = EthernetFrame::new_checked(&buffer);
            // We only care about ARP packets.
            if EthernetFrame::ethertype(&frame.unwrap()) == EthernetProtocol::Arp {
                trace!("{}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
            }
            Ok(())
        }).unwrap();
    }
}

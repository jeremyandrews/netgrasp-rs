use std::os::unix::io::AsRawFd;
use smoltcp::phy::{Device, RxToken, RawSocket};
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{PrettyPrinter, EthernetFrame, EthernetProtocol};
use smoltcp::time::Instant;
use std::sync::mpsc::{Sender};

pub struct ArpPacket {
    pub interface: String,
}

pub fn listen(iface: String, arp_tx: Sender<ArpPacket>) {
    let mut socket = RawSocket::new(iface.as_ref()).unwrap();
    // Creates a raw socket, bound to the interface as named in `interface`.
    // Note: this requires superuser privileges, or corresponding capability bit.
    // Passes ifname as a reference.
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
            let arp_packet = ArpPacket {
                interface: iface.clone(),
            };
            // Be sure we have a valid ethernet frame.
            let frame = EthernetFrame::new_checked(&buffer);
            // We only care about ARP packets.
            if EthernetFrame::ethertype(&frame.unwrap()) == EthernetProtocol::Arp {
                trace!("{}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
                arp_tx.send(arp_packet).unwrap();
            }
            Ok(())
        }).unwrap();
    }
}
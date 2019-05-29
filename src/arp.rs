use std::os::unix::io::AsRawFd;
use smoltcp::phy::{Device, RxToken, RawSocket};
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{PrettyPrinter, EthernetFrame, EthernetProtocol, EthernetAddress, Ipv4Address, ArpPacket, ArpOperation};
use smoltcp::time::Instant;
use std::sync::mpsc::{Sender};

#[derive(Debug)]
pub struct NetgraspArpPacket {
    pub interface: String,
    pub src_mac: EthernetAddress,
    pub src_ip: Ipv4Address,
    pub tgt_mac: EthernetAddress,
    pub tgt_ip: Ipv4Address,
    pub operation: ArpOperation,
}

pub fn listen(iface: String, arp_tx: Sender<NetgraspArpPacket>) {
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
            // Be sure we have a valid ethernet frame.
            // @TODO: handle bad frames (unwrap_or)?
            let frame = EthernetFrame::new_checked(&buffer).unwrap();
            // We only care about ARP packets.
            if EthernetFrame::ethertype(&frame) == EthernetProtocol::Arp {
                let packet = &ArpPacket::new_checked(frame.payload()).unwrap();
                //let arp_repr = ArpRepr::parse(&packet)?;
                let arp_packet = NetgraspArpPacket {
                    interface: iface.clone(),
                    src_mac: EthernetAddress::from_bytes(packet.source_hardware_addr()),
                    src_ip: Ipv4Address::from_bytes(packet.source_protocol_addr()),
                    tgt_mac: EthernetAddress::from_bytes(packet.target_hardware_addr()),
                    tgt_ip: Ipv4Address::from_bytes(packet.target_protocol_addr()),
                    operation: packet.operation(),
                };
                trace!("{}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
                arp_tx.send(arp_packet).unwrap();
            }
            Ok(())
        }).unwrap();
    }
}
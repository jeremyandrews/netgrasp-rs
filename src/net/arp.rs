use std::os::unix::io::AsRawFd;
use smoltcp::phy::{Device, RxToken, RawSocket};
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{PrettyPrinter, EthernetFrame, EthernetProtocol, EthernetAddress, Ipv4Address, ArpPacket, ArpOperation};
use smoltcp::time::Instant;
use std::sync::mpsc::{Sender};

#[derive(Debug)]
pub struct NetgraspArpPacket {
    pub interface: String,
    pub interface_ip: String,
    pub src_mac: EthernetAddress,
    pub src_ip: Ipv4Address,
    pub src_is_self: bool,
    pub src_is_broadcast: bool,
    pub tgt_mac: EthernetAddress,
    pub tgt_ip: Ipv4Address,
    pub tgt_is_self: bool,
    pub tgt_is_broadcast: bool,
    pub operation: ArpOperation,
}

fn get_interface_ip_address(interface: String) -> String {
    let mut ip: String = String::from("");
    for iface in get_if_addrs::get_if_addrs().unwrap() {
        if iface.name == interface {
            ip = iface.ip().to_string();
        }
    }
    debug!("get_interface_ip_address: {}", &ip);
    ip
}

pub fn listen(iface: String, arp_tx: Sender<NetgraspArpPacket>) {
    let mut socket = match RawSocket::new(iface.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            error!("Permission error, unable to open a raw socket on {}. You must run as root. Exiting on error: [{}]", iface, e);
            std::process::exit(1);
        }
    };
    // Creates a raw socket, bound to the interface as named in `interface`.
    // Note: this requires superuser privileges, or corresponding capability bit.
    // Passes ifname as a reference.
    loop {
        trace!("top of listen loop");
        // Logic for listening to ARP packets with smoltcp derived from tcpdump example:
        //   https://github.com/m-labs/smoltcp/blob/master/examples/tcpdump.rs
        // Wait forever for socket raw file descriptor to become readable.
        match phy_wait(socket.as_raw_fd(), None) {
            Ok(_) => (),
            Err(e) => error!("error reading ARP packet on {}: {}", iface, e),
        }
        // Returns both rx and tx as option, we only use the former.
        let (rx_token, _) = match socket.receive() {
            Some(r) => r,
            None => {
                error!("fatal error, empty receive on {}", iface);
                std::process::exit(1);
            }
        };
        // Implemented as a Closure:
        //   https://doc.rust-lang.org/book/ch13-01-closures.html#refactoring-with-closures-to-store-code
        rx_token.consume(Instant::now(), |buffer| {
            // Be sure we have a valid ethernet frame.
            match EthernetFrame::new_checked(&buffer) {
                Ok(f) => {
                    trace!("checking if packet is ARP");
                    // We only care about ARP packets.
                    if EthernetFrame::ethertype(&f) == EthernetProtocol::Arp {
                        let packet = &ArpPacket::new_checked(f.payload()).unwrap();
                        let interface_ip = get_interface_ip_address(iface.clone());
                        let src_ip = Ipv4Address::from_bytes(packet.source_protocol_addr());
                        let tgt_ip = Ipv4Address::from_bytes(packet.target_protocol_addr());
                        let arp_packet = NetgraspArpPacket {
                            interface: iface.clone(),
                            interface_ip: interface_ip.clone(),
                            src_mac: EthernetAddress::from_bytes(packet.source_hardware_addr()),
                            src_ip: src_ip,
                            src_is_self: src_ip.to_string() == interface_ip,
                            src_is_broadcast: EthernetAddress::from_bytes(packet.source_hardware_addr()).is_broadcast(),
                            tgt_mac: EthernetAddress::from_bytes(packet.target_hardware_addr()),
                            tgt_ip: tgt_ip,
                            tgt_is_self: tgt_ip.to_string() == interface_ip,
                            tgt_is_broadcast: EthernetAddress::from_bytes(packet.target_hardware_addr()).is_broadcast(),
                            operation: packet.operation(),
                        };
                        trace!("arp: {}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
                        match arp_tx.send(arp_packet) {
                            Ok(_) => (),
                            Err(e) => error!("failed to send arp packet to main thread: {}", e)
                        }
                    }
                    else {
                        trace!("not arp: {}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
                    }
                }
                Err(e) => error!("Error reading ethernet frame on {}: {}", iface, e),
            };
            Ok(())
        }).unwrap();
    }
}
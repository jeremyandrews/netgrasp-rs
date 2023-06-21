// Listen for arp packets.

use async_trait::async_trait;
use libarp::arp::ArpMessage;
use libarp::client::ArpClient;
use tokio::sync::mpsc;

pub struct ArpPacket {
    pub arp_message: ArpMessage,
    pub ifname: String,
}

#[async_trait]
pub trait ArpClientTrait {
    async fn receive_next(&mut self) -> Option<ArpMessage>;
    // Add other methods as needed
}

#[async_trait]
impl ArpClientTrait for ArpClient {
    async fn receive_next(&mut self) -> Option<ArpMessage> {
        self.receive_next().await
    }
    // Add other methods as needed
}

// Listens for arp packets and sends them through arp_tx.
pub async fn listen_loop<T: ArpClientTrait + Send>(
    mut client: T,
    ifname: String,
    arp_tx: mpsc::Sender<ArpPacket>,
) {
    println!("listening on {}", ifname);
    loop {
        // `receive_next` will return Some() only if it's an Arp packet.
        while let Some(arp_message) = client.receive_next().await {
            if let Err(e) = arp_tx
                .send(ArpPacket {
                    arp_message,
                    ifname: ifname.clone(),
                })
                .await
            {
                println!("receiver dropped: {}", e);
                return;
            }
        }
        // Add a very brief sleep to minimize the CPU load.
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    }
}

#[cfg(test)]
struct MockArpClient {
    messages: Vec<ArpMessage>,
}

#[async_trait]
#[cfg(test)]
impl ArpClientTrait for MockArpClient {
    async fn receive_next(&mut self) -> Option<ArpMessage> {
        self.messages.pop()
    }
    // Add other methods as needed
}

#[cfg(test)]
mod tests {
    use super::*;
    use libarp::arp::ArpMessage;
    use libarp::interfaces::MacAddr;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_listen_loop() {
        let mac_addr = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let source_address = Ipv4Addr::new(192, 168, 1, 1);
        let target_address = Ipv4Addr::new(192, 168, 1, 2);

        // Create a mock ARP message
        let mock_arp_message = ArpMessage::new_arp_request(
            mac_addr.clone(),
            source_address.clone(),
            target_address.clone(),
        );

        // Create a mock ArpClient
        let mock_client = MockArpClient {
            messages: vec![mock_arp_message],
        };

        // Create a channel
        let (tx, mut rx) = mpsc::channel(1);

        // Spawn the listen_loop function in a new task
        tokio::spawn(async move {
            listen_loop(mock_client, "eth0".to_string(), tx).await;
        });

        // Check that the listen_loop function received the ARP message
        if let Some(arp_packet) = rx.recv().await {
            assert_eq!(
                arp_packet.arp_message.source_hardware_address.to_string(),
                mac_addr.to_string()
            );
            assert_eq!(
                arp_packet.arp_message.source_protocol_address.to_string(),
                source_address.to_string()
            );
            assert_eq!(
                arp_packet.arp_message.target_protocol_address.to_string(),
                target_address.to_string()
            );
            assert_eq!(arp_packet.ifname, "eth0");
        } else {
            panic!("Did not receive ARP packet");
        }
    }
}

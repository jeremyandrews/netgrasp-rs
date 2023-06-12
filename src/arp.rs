// Listen for arp packets.

use libarp::arp::ArpMessage;
use libarp::client::ArpClient;
use tokio::sync::mpsc;

pub struct ArpPacket {
    pub arp_message: ArpMessage,
    pub ifname: String,
}

// Listens for arp packets and sends them through arp_tx.
pub async fn listen_loop(ifname: String, arp_tx: mpsc::Sender<ArpPacket>) {
    let mut client = ArpClient::new_with_iface_name(&ifname).unwrap();
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

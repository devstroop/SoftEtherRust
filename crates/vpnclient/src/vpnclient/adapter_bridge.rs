use anyhow::Result;
use rand::RngCore;
use tokio::time::Duration;
use tracing::warn;

#[cfg(feature = "adapter")]
use adapter::VirtualAdapter;

use super::VpnClient;

impl VpnClient {
    /// Start the utun adapter and bi-directional bridging between the adapter and the session/dataplane
    pub(crate) async fn start_adapter_and_bridge(&mut self) -> Result<()> {
        #[cfg(not(feature = "adapter"))]
        {
            // No adapter bridging when the adapter feature is disabled
            self.bridge_ready = false;
            return Ok(());
        }
        // Ensure adapter exists
        #[cfg(feature = "adapter")]
        if self.adapter.is_none() {
            let name = self.config.client.interface_name.clone();
            self.adapter = Some(VirtualAdapter::new(name, None));
            if let Some(adp) = &mut self.adapter {
                adp.create().await?;
            }
        }

        // Get IO handle (macOS) – only when adapter feature is enabled
        #[cfg(all(target_os = "macos", feature = "adapter"))]
        let io = {
            let adp = self.adapter.as_ref().expect("adapter");
            adp.io_handle()?
        };

        // Prefer bridging via dataplane if available to avoid taking session.packet_rx
        let dp_opt = self.dataplane.clone();
        if dp_opt.is_none() {
            warn!("Dataplane not initialized; skipping adapter bridging");
            return Ok(());
        }
        let dp = dp_opt.unwrap();
        // Create adapter<->dataplane channels
        let (adp_to_dp_tx, adp_to_dp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (dp_to_adp_tx, mut dp_to_adp_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        // Register with dataplane
        dp.set_adapter_tx(adp_to_dp_rx); // adapter -> session/dataplane
        dp.set_adapter_rx(dp_to_adp_tx); // session/dataplane -> adapter

        // Task: adapter -> session (read packets from utun and send into session)
        #[cfg(all(target_os = "macos", feature = "adapter"))]
        {
            let io_r = io.clone();
            let tx = adp_to_dp_tx.clone();
            // Generate a stable locally-administered MAC used when wrapping DHCP IP packets into Ethernet frames
            let mut mac = [0u8; 6];
            rand::rng().fill_bytes(&mut mac);
            mac[0] = (mac[0] & 0b1111_1110) | 0b0000_0010; // locally administered, unicast
            let src_mac = mac;
            // Generate a locally-administered MAC for use as source in wrapped Ethernet frames
            fn ip_to_eth_if_dhcp(ip: &[u8], src_mac: [u8; 6]) -> Option<Vec<u8>> {
                if ip.len() < 20 {
                    return None;
                }
                let ver_ihl = ip[0];
                if (ver_ihl >> 4) != 4 {
                    return None;
                } // IPv4 only
                let ihl = (ver_ihl & 0x0f) as usize * 4;
                if ihl < 20 || ip.len() < ihl + 8 {
                    return None;
                }
                let proto = ip[9];
                if proto != 17 {
                    return None;
                } // UDP only
                let src_port = u16::from_be_bytes([ip[ihl], ip[ihl + 1]]);
                let dst_port = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
                let _dst_ip = &ip[16..20];
                let is_dhcp =
                    (src_port == 67 || src_port == 68) || (dst_port == 67 || dst_port == 68);
                if !is_dhcp {
                    return None;
                }
                let mut frame = Vec::with_capacity(14 + ip.len());
                // dest mac: broadcast for DHCP
                frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
                frame.extend_from_slice(&src_mac);
                frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
                frame.extend_from_slice(ip);
                Some(frame)
            }
            let h = tokio::spawn(async move {
                loop {
                    match io_r.read().await {
                        Ok(Some(frame)) => {
                            // frame from utun is an IP packet; wrap to Ethernet only for DHCP to allow server-side DHCP to work
                            if let Some(eth) = ip_to_eth_if_dhcp(&frame, src_mac) {
                                let _ = tx.send(eth);
                            } else {
                                // Non-DHCP IP packets cannot be expressed on Ethernet without ARP/neighbor; drop here
                            }
                        }
                        Ok(None) => {
                            // timeout; loop to check for shutdown
                            continue;
                        }
                        Err(e) => {
                            warn!("adapter->session read error: {}", e);
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
                }
            });
            self.aux_tasks.push(h);
        }

        // Task: session -> adapter (read frames emitted by session and write to utun)
        #[cfg(all(target_os = "macos", feature = "adapter"))]
        {
            let io_w = io.clone();
            // Helper: strip Ethernet header if IPv4 and return IP payload
            fn eth_to_ipv4(frame: &[u8]) -> Option<Vec<u8>> {
                if frame.len() < 14 {
                    return None;
                }
                let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
                if ether_type != 0x0800 {
                    return None;
                }
                Some(frame[14..].to_vec())
            }
            let h = tokio::spawn(async move {
                while let Some(frame) = dp_to_adp_rx.recv().await {
                    // Convert SoftEther L2 frame to utun L3 IP packet when possible
                    if let Some(ipv4) = eth_to_ipv4(&frame) {
                        if let Err(e) = io_w.write(&ipv4).await {
                            warn!("session->adapter write error: {}", e);
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    } else {
                        // Drop non-IPv4 frames (e.g., ARP) as utun can't carry them
                    }
                }
            });
            self.aux_tasks.push(h);
        }

        // Mark bridge as ready once channels/tasks are established
        self.bridge_ready = true;
        Ok(())
    }
}

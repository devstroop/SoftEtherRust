use anyhow::Result;
use tracing::{debug, info, warn};

#[cfg(feature = "adapter")]
use adapter::VirtualAdapter;

use super::VpnClient;

impl VpnClient {
    /// Start the virtual adapter and bi-directional bridging between the adapter and the session/dataplane
    ///
    /// This method creates a virtual network interface and establishes bidirectional packet forwarding
    /// between the adapter and the VPN dataplane. It sets up async tasks for continuous packet processing.
    ///
    /// Process Flow:
    ///   1. Create virtual adapter if not already exists
    ///   2. Set up bidirectional channels for packet forwarding
    ///   3. Spawn async tasks for adapter->dataplane and dataplane->adapter bridging
    ///   4. Mark bridging as ready
    ///
    /// Packet Flow:
    ///   - Adapter -> Dataplane: Reads Ethernet frames from virtual interface, forwards to VPN tunnel
    ///   - Dataplane -> Adapter: Receives decrypted frames from tunnel, writes to virtual interface
    ///
    /// Concurrency:
    ///   - Uses separate async tasks for each direction
    ///   - Tasks run indefinitely until connection closes
    ///   - Errors in one direction don't affect the other
    ///
    /// Parameters:
    ///   - mac_address: Optional MAC address for the virtual adapter
    ///
    /// Returns:
    ///   - Result<()>: Success or error during adapter/bridge setup
    pub(crate) async fn start_adapter_and_bridge(&mut self, mac_address: Option<String>) -> Result<()> {
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
            self.adapter = Some(VirtualAdapter::new(name, mac_address));
            if let Some(adp) = &mut self.adapter {
                adp.create().await?;
            }
        }

        let adapter = self.adapter.as_mut().unwrap();
        let io_handle1 = adapter.io_handle()?;
        let io_handle2 = adapter.io_handle()?;

        // Channel for adapter -> dataplane
        let (adapter_to_dp_tx, adapter_to_dp_rx) = tokio::sync::mpsc::unbounded_channel();
        self.dataplane.as_ref().unwrap().set_adapter_tx(adapter_to_dp_rx);

        // Channel for dataplane -> adapter
        let (dp_to_adapter_tx, mut dp_to_adapter_rx) = tokio::sync::mpsc::unbounded_channel();
        self.dataplane.as_ref().unwrap().set_adapter_rx(dp_to_adapter_tx);

        let task1 = tokio::spawn(async move {
            let io = io_handle1;
            loop {
                match io.read_frame().await {
                    Ok(Some(frame)) => {
                        debug!("Adapter bridge: read frame from adapter, len={}", frame.len());
                        let _ = adapter_to_dp_tx.send(frame);
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        warn!("Adapter bridge: error reading from adapter: {}", e);
                        break;
                    }
                }
            }
        });

        let task2 = tokio::spawn(async move {
            while let Some(frame) = dp_to_adapter_rx.recv().await {
                debug!("Adapter bridge: received frame from dataplane, len={}", frame.len());
                if let Err(e) = io_handle2.write_frame(&frame).await {
                    warn!("Failed to write frame to adapter: {}", e);
                    break;
                } else {
                    debug!("Adapter bridge: wrote frame to adapter, len={}", frame.len());
                }
            }
        });

        self.aux_tasks.push(task1);
        self.aux_tasks.push(task2);

        info!("Adapter bridging started successfully");
        self.bridge_ready = true;
        Ok(())
    }
}

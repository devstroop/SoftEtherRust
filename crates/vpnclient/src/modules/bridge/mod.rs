// Bridge module - placeholder for adapter bridge logic
// This will contain the TUN/TAP and Wintun bridge functionality

use tun_rs::{SyncDevice, DeviceBuilder, Layer};
use tracing::info;

/// Network adapter bridge manager
pub struct BridgeManager {
    device: Option<SyncDevice>,
    adapter_type: AdapterType,
}

/// Adapter type (L2 vs L3)
#[derive(Debug, Clone, PartialEq)]
pub enum AdapterType {
    L2Tap,   // TAP adapter (Ethernet frames)
    L3Tun,   // TUN adapter (IP packets)
    Wintun,  // Windows Wintun (IP packets)
}

impl BridgeManager {
    pub fn new() -> Self {
        Self {
            device: None,
            adapter_type: AdapterType::L3Tun,
        }
    }

    /// Create and configure network adapter
    pub async fn create_adapter(&mut self, name: &str, adapter_type: AdapterType) -> Result<(), Box<dyn std::error::Error>> {
        info!("Creating {} adapter: {}", 
              match adapter_type {
                  AdapterType::L2Tap => "TAP",
                  AdapterType::L3Tun => "TUN", 
                  AdapterType::Wintun => "Wintun",
              }, 
              name);

        let layer = match adapter_type {
            AdapterType::L2Tap => Layer::L2,
            AdapterType::L3Tun | AdapterType::Wintun => Layer::L3,
        };

        let device = DeviceBuilder::new()
            .name(name)
            .layer(layer)
            .build_sync()?;

        self.device = Some(device);
        self.adapter_type = adapter_type;

        info!("Network adapter created successfully");
        Ok(())
    }

    /// Get adapter type
    pub fn get_adapter_type(&self) -> &AdapterType {
        &self.adapter_type
    }

    /// Check if adapter is L2 (Ethernet frames)
    pub fn is_l2_adapter(&self) -> bool {
        self.adapter_type == AdapterType::L2Tap
    }

    /// Get device reference
    pub fn get_device(&mut self) -> Option<&mut SyncDevice> {
        self.device.as_mut()
    }
}

impl Default for BridgeManager {
    fn default() -> Self {
        Self::new()
    }
}
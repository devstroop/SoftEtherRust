// DHCP packet handler - inspired by Go's cedar/dhcp_packet_handler.go
// Handles DHCP packet processing and forwarding

use super::types::{DhcpOptions, DhcpMetrics};
use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// DHCP packet handler for managing DHCP traffic
pub struct DhcpPacketHandler {
    pending_requests: HashMap<u32, mpsc::UnboundedSender<DhcpOptions>>,
    mac_address: [u8; 6],
    metrics: Arc<DhcpMetrics>,
}

impl DhcpPacketHandler {
    /// Create a new DHCP packet handler
    pub fn new(mac_address: [u8; 6]) -> Self {
        Self {
            pending_requests: HashMap::new(),
            mac_address,
            metrics: Arc::new(DhcpMetrics::new()),
        }
    }

    /// Register a pending DHCP request
    pub fn register_request(&mut self, transaction_id: u32, response_tx: mpsc::UnboundedSender<DhcpOptions>) {
        self.pending_requests.insert(transaction_id, response_tx);
        debug!("Registered DHCP request with XID: {:08x}", transaction_id);
    }

    /// Process incoming DHCP packet
    pub fn process_dhcp_packet(&mut self, packet: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Parse transaction ID from packet
        let transaction_id = self.extract_transaction_id(packet)?;
        
        // Check if we have a pending request for this transaction
        if let Some(response_tx) = self.pending_requests.remove(&transaction_id) {
            // Parse full DHCP options
            let options = self.parse_dhcp_response(packet)?;
            
            // Send response to waiting client
            if let Err(_) = response_tx.send(options) {
                warn!("Failed to send DHCP response to waiting client");
            } else {
                debug!("Delivered DHCP response for XID: {:08x}", transaction_id);
            }
        } else {
            debug!("Received DHCP packet for unknown transaction: {:08x}", transaction_id);
        }
        
        Ok(())
    }

    /// Extract transaction ID from DHCP packet
    fn extract_transaction_id(&self, packet: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
        // Skip Ethernet (14) + IP (20) + UDP (8) headers = 42 bytes for L2
        // Skip IP (20) + UDP (8) headers = 28 bytes for L3
        let offset = if packet.len() > 42 && packet[12] == 0x08 && packet[13] == 0x00 {
            42 // L2 (Ethernet frame)
        } else {
            28 // L3 (IP packet)
        };
        
        if packet.len() < offset + 8 {
            return Err("Packet too short for DHCP".into());
        }
        
        let dhcp_data = &packet[offset..];
        let transaction_id = u32::from_be_bytes([dhcp_data[4], dhcp_data[5], dhcp_data[6], dhcp_data[7]]);
        
        Ok(transaction_id)
    }

    /// Parse DHCP response packet
    fn parse_dhcp_response(&self, packet: &[u8]) -> Result<DhcpOptions, Box<dyn std::error::Error>> {
        // Similar to client parsing but more robust
        let offset = if packet.len() > 42 && packet[12] == 0x08 && packet[13] == 0x00 {
            42 // L2 (Ethernet frame)
        } else {
            28 // L3 (IP packet)
        };
        
        if packet.len() < offset + 240 {
            return Err("DHCP packet too short".into());
        }
        
        let dhcp_data = &packet[offset..];
        
        // Verify magic cookie
        let magic = u32::from_be_bytes([dhcp_data[236], dhcp_data[237], dhcp_data[238], dhcp_data[239]]);
        if magic != DHCP_MAGIC_COOKIE {
            return Err("Invalid DHCP magic cookie".into());
        }
        
        let mut options = DhcpOptions {
            client_address: u32::from_be_bytes([dhcp_data[16], dhcp_data[17], dhcp_data[18], dhcp_data[19]]),
            ..Default::default()
        };
        
        // Parse options
        self.parse_options(&dhcp_data[240..], &mut options)?;
        
        debug!("Parsed DHCP response: type={}, client_ip={}, server_ip={}", 
               options.opcode, 
               self.uint32_to_ip(options.client_address),
               self.uint32_to_ip(options.server_address));
        
        Ok(options)
    }

    /// Parse DHCP options section
    fn parse_options(&self, data: &[u8], options: &mut DhcpOptions) -> Result<(), Box<dyn std::error::Error>> {
        let mut i = 0;
        
        while i < data.len() {
            let option_type = data[i];
            i += 1;
            
            if option_type == DHCP_ID_END {
                break;
            }
            
            if i >= data.len() {
                break;
            }
            
            let option_len = data[i] as usize;
            i += 1;
            
            if i + option_len > data.len() {
                break;
            }
            
            let option_data = &data[i..i + option_len];
            
            match option_type {
                DHCP_ID_MESSAGE_TYPE if option_len == 1 => {
                    options.opcode = option_data[0];
                }
                DHCP_ID_SUBNET_MASK if option_len == 4 => {
                    options.subnet_mask = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                DHCP_ID_GATEWAY if option_len >= 4 => {
                    options.gateway = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                DHCP_ID_DNS_SERVER if option_len >= 4 => {
                    options.dns_server = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                    if option_len >= 8 {
                        options.dns_server2 = u32::from_be_bytes([option_data[4], option_data[5], option_data[6], option_data[7]]);
                    }
                }
                DHCP_ID_LEASE_TIME if option_len == 4 => {
                    options.lease_time = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                DHCP_ID_SERVER_ADDRESS if option_len == 4 => {
                    options.server_address = u32::from_be_bytes([option_data[0], option_data[1], option_data[2], option_data[3]]);
                }
                _ => {
                    debug!("Unhandled DHCP option: {} (len={})", option_type, option_len);
                }
            }
            
            i += option_len;
        }
        
        Ok(())
    }

    /// Helper to convert u32 to IP string
    fn uint32_to_ip(&self, ip: u32) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(ip.to_be_bytes())
    }

    /// Get metrics snapshot
    pub fn get_metrics(&self) -> Arc<DhcpMetrics> {
        self.metrics.clone()
    }
}
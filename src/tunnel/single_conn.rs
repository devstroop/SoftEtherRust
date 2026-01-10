//! Single-connection data loop for tunnel runner.
//!
//! This module contains the main packet forwarding loop for single TCP connection mode.
//! Supports macOS, Linux, and Windows platforms with platform-specific TUN handling.

use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::adapter::TunAdapter;
#[cfg(target_os = "windows")]
use crate::adapter::WintunDevice;
use crate::client::VpnConnection;
use crate::error::Result;
use crate::packet::{ArpHandler, DhcpConfig, BROADCAST_MAC};
#[cfg(target_os = "windows")]
use crate::protocol::compress;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::protocol::compress_into;
use crate::protocol::{decompress_into, is_compressed, TunnelCodec};

use super::packet_processor::{
    init_arp, send_keepalive_if_needed, send_pending_arp_reply, send_periodic_garp_if_needed,
};
use super::DataLoopState;
use super::TunnelRunner;

impl TunnelRunner {
    /// Run the main data forwarding loop.
    ///
    /// Zero-copy optimized path:
    /// - Outbound: TUN read → inline Ethernet wrap → direct send
    /// - Inbound: Network read → direct TUN write (skip Ethernet header)
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) async fn run_data_loop(
        &self,
        conn: &mut VpnConnection,
        tun: &mut impl TunAdapter,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        self.run_data_loop_unix(conn, tun, dhcp_config).await
    }

    #[cfg(target_os = "windows")]
    pub(super) async fn run_data_loop(
        &self,
        conn: &mut VpnConnection,
        tun: &mut WintunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        self.run_data_loop_windows(conn, tun, dhcp_config).await
    }

    /// Unix-specific data loop implementation using libc poll/read.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn run_data_loop_unix(
        &self,
        conn: &mut VpnConnection,
        tun: &mut impl TunAdapter,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        let mut codec = TunnelCodec::new();

        // Initialize RC4 encryption if enabled
        let mut encryption = self.create_encryption();
        if encryption.is_some() {
            info!("RC4 encryption active for tunnel data");
        }

        // Pre-allocated buffers - sized for maximum packets
        let mut net_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 4096];
        let mut decomp_buf = vec![0u8; 4096];
        let mut comp_buf = vec![0u8; 4096];
        let mut tun_write_buf = vec![0u8; 2048];

        // Set up ARP handler and send initial ARP packets
        let mut arp = ArpHandler::new(self.mac);
        init_arp(
            conn,
            &mut arp,
            dhcp_config.ip,
            gateway,
            &mut send_buf,
            &mut encryption,
        )
        .await?;

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        // Zero-copy TUN reader using fixed buffer
        let (tun_tx, mut tun_rx) = mpsc::channel::<(usize, [u8; 2048])>(256);
        let tun_fd = tun.raw_fd();
        let running = self.running.clone();

        // Spawn blocking TUN reader task
        let tun_reader = tokio::task::spawn_blocking(move || {
            let mut read_buf = [0u8; 2048];

            while running.load(Ordering::SeqCst) {
                let mut poll_fds = [libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];

                let poll_result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 1, 1) };

                if poll_result > 0 && (poll_fds[0].revents & libc::POLLIN) != 0 {
                    let n = unsafe {
                        libc::read(
                            tun_fd,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };

                    #[cfg(target_os = "macos")]
                    let min_len = 4;
                    #[cfg(target_os = "linux")]
                    let min_len = 1;

                    if n > min_len as isize && tun_tx.blocking_send((n as usize, read_buf)).is_err()
                    {
                        break;
                    }
                }
            }
        });

        info!("VPN tunnel active");

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                biased;

                Some((len, tun_buf)) = tun_rx.recv() => {
                    #[cfg(target_os = "macos")]
                    let ip_packet = &tun_buf[4..len];
                    #[cfg(target_os = "linux")]
                    let ip_packet = &tun_buf[..len];

                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress_into(eth_frame, &mut comp_buf) {
                            Ok(comp_len) => {
                                let comp_total = 8 + comp_len;
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8].copy_from_slice(&(comp_len as u32).to_be_bytes());
                                    send_buf[8..8 + comp_len].copy_from_slice(&comp_buf[..comp_len]);
                                    if let Some(ref mut enc) = encryption {
                                        enc.encrypt(&mut send_buf[..comp_total]);
                                    }
                                    conn.write_all(&send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                if let Some(ref mut enc) = encryption {
                                    enc.encrypt(&mut send_buf[..total_len]);
                                }
                                conn.write_all(&send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(ip_packet);

                        if let Some(ref mut enc) = encryption {
                            enc.encrypt(&mut send_buf[..total_len]);
                        }
                        conn.write_all(&send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                result = conn.read(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            if let Some(ref mut enc) = encryption {
                                enc.decrypt(&mut net_buf[..n]);
                            }

                            match codec.feed(&net_buf[..n]) {
                                Ok(frames) => {
                                    for frame in frames {
                                        if frame.is_keepalive() {
                                            debug!("Received keepalive");
                                            continue;
                                        }

                                        if let Some(packets) = frame.packets() {
                                            for packet in packets {
                                                let frame_data: &[u8] = if is_compressed(packet) {
                                                    match decompress_into(packet, &mut decomp_buf) {
                                                        Ok(len) => &decomp_buf[..len],
                                                        Err(_) => continue,
                                                    }
                                                } else {
                                                    packet
                                                };

                                                if let Err(e) = self.process_frame_zerocopy(
                                                    tun_fd,
                                                    &mut tun_write_buf,
                                                    &mut arp,
                                                    frame_data,
                                                    our_ip,
                                                ) {
                                                    error!("Process error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Decode error: {}", e);
                                }
                            }

                            send_pending_arp_reply(conn, &mut arp, &mut send_buf, &mut encryption).await?;
                            last_activity = Instant::now();
                        }
                        Ok(_) => {
                            warn!("Server closed connection");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Network read failed");
                            break;
                        }
                    }
                }

                _ = keepalive_interval.tick() => {
                    send_keepalive_if_needed(conn, last_activity, &mut send_buf, &mut encryption).await?;
                    send_periodic_garp_if_needed(conn, &mut arp, &mut send_buf, &mut encryption).await?;
                }
            }
        }

        info!("VPN tunnel stopped");
        tun_reader.abort();
        Ok(())
    }

    /// Windows-specific data loop implementation using Wintun.
    #[cfg(target_os = "windows")]
    async fn run_data_loop_windows(
        &self,
        conn: &mut VpnConnection,
        tun: &mut WintunDevice,
        dhcp_config: &DhcpConfig,
    ) -> Result<()> {
        let mut state = DataLoopState::new(self.mac);
        let gateway = dhcp_config.gateway.unwrap_or(dhcp_config.ip);
        state.configure(dhcp_config.ip, gateway);

        let mut codec = TunnelCodec::new();

        let mut encryption = self.create_encryption();
        if encryption.is_some() {
            info!("RC4 encryption active for tunnel data (Windows)");
        }

        let mut net_buf = vec![0u8; 65536];
        let mut send_buf = vec![0u8; 4096];
        let mut decomp_buf = vec![0u8; 4096];

        let mut arp = ArpHandler::new(self.mac);
        init_arp(
            conn,
            &mut arp,
            dhcp_config.ip,
            gateway,
            &mut send_buf,
            &mut encryption,
        )
        .await?;

        let mut keepalive_interval = interval(Duration::from_secs(self.config.keepalive_interval));
        let mut last_activity = Instant::now();

        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let session = tun.session();
        let running = self.running.clone();

        let tun_reader = tokio::task::spawn_blocking(move || {
            let mut idle_count = 0u32;

            while running.load(Ordering::SeqCst) {
                match session.try_receive() {
                    Ok(Some(packet)) => {
                        let bytes = packet.bytes().to_vec();
                        if tun_tx.blocking_send(bytes).is_err() {
                            break;
                        }
                        idle_count = 0;
                    }
                    Ok(None) => {
                        idle_count += 1;
                        if idle_count > 100 {
                            match session.receive_blocking() {
                                Ok(packet) => {
                                    let bytes = packet.bytes().to_vec();
                                    if tun_tx.blocking_send(bytes).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    std::thread::sleep(Duration::from_micros(100));
                                }
                            }
                            idle_count = 0;
                        } else {
                            std::thread::yield_now();
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_micros(100));
                        idle_count = 0;
                    }
                }
            }
        });

        info!("VPN tunnel active (Windows)");

        let our_ip = dhcp_config.ip;
        let use_compress = self.config.use_compress;
        let my_mac = self.mac;

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                biased;

                Some(ip_packet) = tun_rx.recv() => {
                    if ip_packet.is_empty() {
                        continue;
                    }

                    let gateway_mac = arp.gateway_mac_or_broadcast();
                    let eth_len = 14 + ip_packet.len();
                    let total_len = 8 + eth_len;

                    if total_len > send_buf.len() {
                        warn!("Packet too large: {}", ip_packet.len());
                        continue;
                    }

                    let ip_version = (ip_packet[0] >> 4) & 0x0F;
                    if ip_version != 4 && ip_version != 6 {
                        continue;
                    }

                    if use_compress {
                        let eth_start = 8;
                        send_buf[eth_start..eth_start + 6].copy_from_slice(&gateway_mac);
                        send_buf[eth_start + 6..eth_start + 12].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[eth_start + 12] = 0x08;
                            send_buf[eth_start + 13] = 0x00;
                        } else {
                            send_buf[eth_start + 12] = 0x86;
                            send_buf[eth_start + 13] = 0xDD;
                        }
                        send_buf[eth_start + 14..eth_start + 14 + ip_packet.len()]
                            .copy_from_slice(&ip_packet);

                        let eth_frame = &send_buf[eth_start..eth_start + eth_len];

                        match compress(eth_frame) {
                            Ok(compressed) => {
                                let comp_total = 8 + compressed.len();
                                if comp_total <= send_buf.len() {
                                    send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                    send_buf[4..8]
                                        .copy_from_slice(&(compressed.len() as u32).to_be_bytes());
                                    send_buf[8..8 + compressed.len()].copy_from_slice(&compressed);
                                    if let Some(ref mut enc) = encryption {
                                        enc.encrypt(&mut send_buf[..comp_total]);
                                    }
                                    conn.write_all(&send_buf[..comp_total]).await?;
                                }
                            }
                            Err(e) => {
                                warn!("Compression failed: {}", e);
                                send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                                send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                                if let Some(ref mut enc) = encryption {
                                    enc.encrypt(&mut send_buf[..total_len]);
                                }
                                conn.write_all(&send_buf[..total_len]).await?;
                            }
                        }
                    } else {
                        send_buf[0..4].copy_from_slice(&1u32.to_be_bytes());
                        send_buf[4..8].copy_from_slice(&(eth_len as u32).to_be_bytes());
                        send_buf[8..14].copy_from_slice(&gateway_mac);
                        send_buf[14..20].copy_from_slice(&my_mac);
                        if ip_version == 4 {
                            send_buf[20] = 0x08;
                            send_buf[21] = 0x00;
                        } else {
                            send_buf[20] = 0x86;
                            send_buf[21] = 0xDD;
                        }
                        send_buf[22..22 + ip_packet.len()].copy_from_slice(&ip_packet);

                        if let Some(ref mut enc) = encryption {
                            enc.encrypt(&mut send_buf[..total_len]);
                        }
                        conn.write_all(&send_buf[..total_len]).await?;
                    }

                    last_activity = Instant::now();
                }

                result = conn.read(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            if let Some(ref mut enc) = encryption {
                                enc.decrypt(&mut net_buf[..n]);
                            }

                            match codec.feed(&net_buf[..n]) {
                                Ok(frames) => {
                                    for frame in frames {
                                        if frame.is_keepalive() {
                                            debug!("Received keepalive");
                                            continue;
                                        }

                                        if let Some(packets) = frame.packets() {
                                            for packet in packets {
                                                let frame_data: &[u8] = if is_compressed(packet) {
                                                    match decompress_into(packet, &mut decomp_buf) {
                                                        Ok(len) => &decomp_buf[..len],
                                                        Err(_) => continue,
                                                    }
                                                } else {
                                                    packet
                                                };

                                                if let Err(e) = self.process_frame_windows(
                                                    tun,
                                                    &mut arp,
                                                    frame_data,
                                                    our_ip,
                                                ) {
                                                    error!("Process error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Decode error: {}", e);
                                }
                            }

                            send_pending_arp_reply(conn, &mut arp, &mut send_buf, &mut encryption).await?;
                            last_activity = Instant::now();
                        }
                        Ok(_) => {
                            warn!("Server closed connection");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Network read failed");
                            break;
                        }
                    }
                }

                _ = keepalive_interval.tick() => {
                    send_keepalive_if_needed(conn, last_activity, &mut send_buf, &mut encryption).await?;
                    send_periodic_garp_if_needed(conn, &mut arp, &mut send_buf, &mut encryption).await?;
                }
            }
        }

        info!("VPN tunnel stopped");
        tun_reader.abort();
        Ok(())
    }

    /// Process an incoming frame for Windows (using Wintun).
    #[cfg(target_os = "windows")]
    #[inline]
    pub(super) fn process_frame_windows(
        &self,
        tun: &mut WintunDevice,
        arp: &mut ArpHandler,
        frame: &[u8],
        our_ip: Ipv4Addr,
    ) -> Result<()> {
        if frame.len() < 14 {
            return Ok(());
        }

        let dst_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        if dst_mac != self.mac && dst_mac != BROADCAST_MAC {
            return Ok(());
        }

        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

        match ether_type {
            0x0800 => {
                // IPv4
                let ip_packet = &frame[14..];
                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

                    if dst_ip == our_ip || dst_ip.is_broadcast() || dst_ip.is_multicast() {
                        let _ = tun.write(ip_packet);
                    }
                }
            }
            0x86DD => {
                // IPv6
                let ip_packet = &frame[14..];
                let _ = tun.write(ip_packet);
            }
            0x0806 => {
                // ARP
                debug!("Received ARP packet ({} bytes)", frame.len());
                if let Some(_reply) = arp.process_arp(frame) {
                    debug!("ARP reply queued");
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Process an incoming frame with zero-copy TUN write (Unix only).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[inline]
    #[allow(unused_variables)]
    pub(super) fn process_frame_zerocopy(
        &self,
        tun_fd: i32,
        tun_buf: &mut [u8],
        arp: &mut ArpHandler,
        frame: &[u8],
        our_ip: Ipv4Addr,
    ) -> Result<()> {
        if frame.len() < 14 {
            return Ok(());
        }

        let dst_mac: [u8; 6] = frame[0..6].try_into().unwrap();
        if dst_mac != self.mac && dst_mac != BROADCAST_MAC {
            return Ok(());
        }

        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);

        match ether_type {
            0x0800 => {
                // IPv4
                let ip_packet = &frame[14..];
                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

                    if dst_ip == our_ip || dst_ip.is_broadcast() || dst_ip.is_multicast() {
                        #[cfg(target_os = "macos")]
                        {
                            let total_len = 4 + ip_packet.len();
                            if total_len <= tun_buf.len() {
                                tun_buf[0..4]
                                    .copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
                                tun_buf[4..total_len].copy_from_slice(ip_packet);
                                unsafe {
                                    libc::write(
                                        tun_fd,
                                        tun_buf.as_ptr() as *const libc::c_void,
                                        total_len,
                                    );
                                }
                            }
                        }
                        #[cfg(target_os = "linux")]
                        {
                            unsafe {
                                libc::write(
                                    tun_fd,
                                    ip_packet.as_ptr() as *const libc::c_void,
                                    ip_packet.len(),
                                );
                            }
                        }
                    }
                }
            }
            0x86DD => {
                // IPv6
                let ip_packet = &frame[14..];
                #[cfg(target_os = "macos")]
                {
                    let total_len = 4 + ip_packet.len();
                    if total_len <= tun_buf.len() {
                        tun_buf[0..4].copy_from_slice(&(libc::AF_INET6 as u32).to_be_bytes());
                        tun_buf[4..total_len].copy_from_slice(ip_packet);
                        unsafe {
                            libc::write(tun_fd, tun_buf.as_ptr() as *const libc::c_void, total_len);
                        }
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    unsafe {
                        libc::write(
                            tun_fd,
                            ip_packet.as_ptr() as *const libc::c_void,
                            ip_packet.len(),
                        );
                    }
                }
            }
            0x0806 => {
                // ARP
                debug!("Received ARP packet ({} bytes)", frame.len());
                if let Some(_reply) = arp.process_arp(frame) {
                    debug!("ARP reply queued");
                }
            }
            _ => {}
        }

        Ok(())
    }
}

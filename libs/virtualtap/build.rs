// Build script for VirtualTap C library

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let virtual_tap_src = manifest_dir.parent().unwrap().parent().unwrap().join("VirtualTap/src");
    
    println!("cargo:rerun-if-changed=../../VirtualTap/src");
    println!("cargo:rerun-if-changed=../../VirtualTap/include");
    
    // Build VirtualTap C library
    cc::Build::new()
        .file(virtual_tap_src.join("virtual_tap.c"))
        .file(virtual_tap_src.join("translator.c"))
        .file(virtual_tap_src.join("arp_handler.c"))
        .file(virtual_tap_src.join("dhcp_builder.c"))
        .file(virtual_tap_src.join("dhcp_parser.c"))
        .file(virtual_tap_src.join("dns_handler.c"))
        .file(virtual_tap_src.join("fragment_handler.c"))
        .file(virtual_tap_src.join("icmp_handler.c"))
        .file(virtual_tap_src.join("icmpv6_handler.c"))
        .file(virtual_tap_src.join("ip_utils.c"))
        .file(virtual_tap_src.join("tun_device.c"))
        .include(manifest_dir.parent().unwrap().parent().unwrap().join("VirtualTap/include"))
        .warnings(false) // Suppress C warnings
        .compile("virtualtap");
}

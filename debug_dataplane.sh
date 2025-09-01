#!/bin/bash
# DataPlane Debug Test Script

echo "🔍 Testing DataPlane Frame Flow Debug"
echo "======================================"

# Build with debug logging
echo "Building with debug logging..."
cd /Volumes/EXT/SoftEtherUnofficial/SoftEtherClient
export RUST_LOG="debug,cedar::dataplane=debug,vpnclient=debug"

# Clean and build
cargo clean
cargo build -p vpnclient

# Test with existing config
echo ""
echo "🚀 Running with enhanced debug logging..."
echo "Watch for these key debug messages:"
echo "  - 'DataPlane scheduler started'"
echo "  - 'TAP bridge RX/TX task started'"  
echo "  - 'DataPlane link RX: forwarding X frames'"
echo "  - 'TAP bridge: received X bytes from DataPlane/TAP'"
echo ""

# Run with debug output
timeout 30s cargo run -p vpnclient -- --config config.json 2>&1 | tee debug_output.log

echo ""
echo "📊 Debug Analysis:"
echo "=================="

# Analyze the debug output
echo "DataPlane scheduler activity:"
grep -c "DataPlane scheduler:" debug_output.log || echo "❌ No DataPlane scheduler activity found"

echo "TAP bridge activity:"
grep -c "TAP bridge:" debug_output.log || echo "❌ No TAP bridge activity found"

echo "Frame forwarding:"
grep -c "forwarding.*frames" debug_output.log || echo "❌ No frame forwarding activity found"

echo "Link registration:"
grep -c "dataplane link registered" debug_output.log || echo "❌ No link registration found"

echo ""
echo "🎯 Key Issues to Check:"
echo "1. Are DataPlane links being registered?"
echo "2. Is the TAP bridge receiving frames from DataPlane?"
echo "3. Is DataPlane receiving frames from session?"
echo "4. Are frames being forwarded between components?"

echo ""
echo "📝 Debug log saved to: debug_output.log"

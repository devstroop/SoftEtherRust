//
//  VirtualTapRust.swift
//  Swift wrapper for VirtualTapRust Rust library
//
//  Provides a safe Swift interface to the VirtualTapRust FFI
//

import Foundation

/// Swift wrapper for VirtualTapRust
public class VirtualTapRust {
    private var handle: OpaquePointer?
    
    public struct Statistics {
        public let packetsWritten: UInt64
        public let packetsRead: UInt64
        public let bytesWritten: UInt64
        public let bytesRead: UInt64
        public let drops: UInt64
    }
    
    public enum Error: Swift.Error {
        case creationFailed
        case invalidHandle
        case bufferFull
        case bufferEmpty
        case operationFailed
        case invalidParameter
    }
    
    /// Create a new VirtualTapRust adapter
    ///
    /// - Parameters:
    ///   - mac: MAC address (6 bytes)
    ///   - mtu: Maximum transmission unit size
    /// - Throws: Error if creation fails
    public init(mac: [UInt8], mtu: Int = 1500) throws {
        guard mac.count == 6 else {
            throw Error.invalidParameter
        }
        
        handle = vtap_create(mac, mtu)
        guard handle != nil else {
            throw Error.creationFailed
        }
    }
    
    deinit {
        if let handle = handle {
            vtap_destroy(handle)
        }
    }
    
    /// Get the interface name (e.g., "utun2")
    public var interfaceName: String? {
        guard let handle = handle else { return nil }
        guard let cString = vtap_get_interface_name(handle) else { return nil }
        return String(cString: cString)
    }
    
    /// Get the file descriptor for the utun device
    public var fileDescriptor: Int32 {
        guard let handle = handle else { return -1 }
        return vtap_get_fd(handle)
    }
    
    /// Write a packet to the ring buffer (utun → VPN direction)
    ///
    /// - Parameter data: Packet data to write
    /// - Throws: Error if write fails
    public func writePacket(_ data: Data) throws {
        guard let handle = handle else {
            throw Error.invalidHandle
        }
        
        let result = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> VTapResult in
            guard let baseAddress = bytes.baseAddress else {
                return VTapError
            }
            return vtap_write_packet(handle, baseAddress.assumingMemoryBound(to: UInt8.self), data.count)
        }
        
        try checkResult(result)
    }
    
    /// Read a packet from the ring buffer (VPN → utun direction)
    ///
    /// - Returns: Packet data, or nil if buffer is empty
    /// - Throws: Error if read fails
    public func readPacket() throws -> Data? {
        guard let handle = handle else {
            throw Error.invalidHandle
        }
        
        var buffer = Data(count: 2048) // Max packet size
        var outLen: Int = 0
        
        let result = buffer.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) -> VTapResult in
            guard let baseAddress = bytes.baseAddress else {
                return VTapError
            }
            return vtap_read_packet(handle, baseAddress.assumingMemoryBound(to: UInt8.self), buffer.count, &outLen)
        }
        
        if result.rawValue == VTapBufferEmpty.rawValue {
            return nil
        }
        
        try checkResult(result)
        
        buffer.count = outLen
        return buffer
    }
    
    /// Get ring buffer statistics
    public var statistics: Statistics {
        get throws {
            guard let handle = handle else {
                throw Error.invalidHandle
            }
            
            var stats = VTapStats()
            let result = vtap_get_stats(handle, &stats)
            try checkResult(result)
            
            return Statistics(
                packetsWritten: stats.packets_written,
                packetsRead: stats.packets_read,
                bytesWritten: stats.bytes_written,
                bytesRead: stats.bytes_read,
                drops: stats.drops
            )
        }
    }
    
    /// Reset ring buffer statistics
    public func resetStatistics() throws {
        guard let handle = handle else {
            throw Error.invalidHandle
        }
        
        let result = vtap_reset_stats(handle)
        try checkResult(result)
    }
    
    // MARK: - Private
    
    private func checkResult(_ result: VTapResult) throws {
        switch result.rawValue {
        case VTapSuccess.rawValue:
            return
        case VTapBufferFull.rawValue:
            throw Error.bufferFull
        case VTapBufferEmpty.rawValue:
            throw Error.bufferEmpty
        case VTapInvalidHandle.rawValue:
            throw Error.invalidHandle
        case VTapInvalidParameter.rawValue:
            throw Error.invalidParameter
        default:
            throw Error.operationFailed
        }
    }
}

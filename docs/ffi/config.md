# FFI Config reference

The JSON config used by `softether_client_create` maps to `crates/config::ClientConfig`.

## Fields

- server: string, hostname or IP of SoftEther server or VPN Azure hostname
- port: number, TCP port (e.g., 443)
- hub: string, virtual hub name
- username: string, account name
- password: string|null, optional if hashes provided
- password_hash: string|null, base64 of 20-byte SHA-0(password + UPPER(username)) [preferred]
- skip_tls_verify: bool, skip TLS verification (development only)
- use_compress: bool, enable LZ4 compression
- use_encrypt: bool, enable encryption (recommended)
- max_connections: number, number of parallel data links (1..N)
- udp_port: number|null, reserved for future UDP acceleration path

## Password guidance

Preferred is to supply the plain password; the client derives required hashes.

If you can't store plain passwords:
- Use `password_hash` = base64(SHA0(password + UPPER(username))).
- Or provide `password_hash` for compatibility with Go genpwdhash. Servers accepting this path typically also accept the 20-byte secure password derived during handshake.

## Example

```
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "DEFAULT",
  "username": "user1",
  "password_hash": "T2kl2mB84H5y2tn7n9qf65/8jXI=",
  "use_compress": false,
  "use_encrypt": true,
  "max_connections": 1,
  "skip_tls_verify": false
}
```

# Changelog

## Unreleased
### Removed
- `use_encrypt` configuration field and protocol pack elements. Encryption is now implicit (TLS mandatory) and no longer negotiable; any previous attempts to set it false would have failed. Handshake/login and additional_connect packs no longer send `use_encrypt`.

### Changed
- `ClientOption::with_encryption` removed (was a no-op). All connections are always encrypted; external callers should drop any usage.

### Notes
- If integrating with legacy tooling expecting `use_encrypt`, no action required; the absent field is treated as encrypted because the transport is TLS.

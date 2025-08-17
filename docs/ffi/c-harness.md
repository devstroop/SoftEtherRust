# Desktop C harness (optional)

A tiny C program to smoke-test the FFI on macOS/Linux.

## Build the library

- Build the cdylib:
  - macOS: `target/release/libsoftether_c_api.dylib`
  - Linux: `target/release/libsoftether_c_api.so`

## Example program

`crates/ffi/c_api/examples/ffi_harness.c` demonstrates creating a client, setting callbacks, connecting, then disconnecting.

To build on macOS (adjust paths):

```
cc -Icrates/ffi/c_api/include -Ltarget/release -lsoftether_c_api \
   -Wl,-rpath,@executable_path/../lib \
   crates/ffi/c_api/examples/ffi_harness.c -o ./ffi_harness
```

Run:

```
DYLD_LIBRARY_PATH=target/release ./ffi_harness
```

On Linux, replace `DYLD_LIBRARY_PATH` with `LD_LIBRARY_PATH`.

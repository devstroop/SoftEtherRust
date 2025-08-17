# Desktop C harness (optional)

A tiny C program to smoke-test the FFI on macOS/Linux.

## Build the library

- Build the cdylib:
  - macOS: `target/release/libsoftether_ffi.dylib`
  - Linux: `target/release/libsoftether_ffi.so`

## Example program

`crates/ffi/examples/ffi_harness.c` demonstrates creating a client, setting callbacks, connecting, then disconnecting.

To build on macOS (adjust paths):

```
cc -Icrates/ffi/include -Ltarget/release -lsoftether_ffi \
   -Wl,-rpath,@executable_path/../lib \
   crates/ffi/examples/ffi_harness.c -o ./ffi_harness
```

Run:

```
DYLD_LIBRARY_PATH=target/release ./ffi_harness
```

On Linux, replace `DYLD_LIBRARY_PATH` with `LD_LIBRARY_PATH`.

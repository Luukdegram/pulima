# Pūlima

Pūlima is both a CLI tool and a library that allows its users to sign WebAssembly modules.
The CLI tool is a small wrapper using the library to allow the users to generate keypairs,
sign the module as well as verify the signature of an existing signed WebAssembly module.
The library is implemented as per the signature specification as defined in the WebAssembly
[tools-convention](https://github.com/WebAssembly/tool-conventions/blob/main/Signatures.md).

Note: This also includes the `content-type` identifier addition as described here:
https://github.com/wasm-signatures/design/pull/9. This allows us to be compatible with
other implementations. (We currently do not support backwards compatibility for cases where
the content-type is missing).

## Features
- [x] Signing & verifying WebAssembly modules
- [ ] Detached signatures
- [ ] Multiple signatures


## CLI

### Features
 - [x] Signing & verifying WebAssembly modules
 - [ ] Detached signatures
 - [ ] Verifying multiple signed sections
 - [x] Generating keys for signing and verifying

### Usage
```
USAGE:
    Pulima [SUBCOMMAND] file [FLAGS]

FLAGS:
    -h, --help            Prints help information
    -o [path]             Output path of the signed binary
    -v                    Verbose output
    -s [path]             The key file to sign the binary module with, or to write the secret key component to
    -p [path]             The public key to verify a signature for, or to write the public key component to
SUBCOMMANDS:
    sign                  Signs a Wasm binary using a private key
    verify                Verifies the signature of a Wasm binary from a public key
    keygen                Generates a new secret and public key pair
```

### Installing

To install the CLI tool in the folder `~/.local`:
```sh
zig build -p ~/.local -Drelease-safe
```
This will install a binary called `pulima` at `~/.local/bin/pulima`

## Using the library

Pūlima can also be used as a library, which is as simply as adding `src/lib.zig` as a package to your `build.zig` file:
```zig
exe.addPackagePath("punima", "libs/punima/src/lib.zig"); // where 'lib/punima' is the folder where the library is installed
```

## Docs

This project makes use of the experimental Zig toolchain feature: autodocs. The following command will generate
documentation for the library in a folder named `docs`:
```sh
zig build docs
```

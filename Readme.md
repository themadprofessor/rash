# Rash
## A file hashing tool written in Rust

Command line application for calculating the hash value of a file. Rash uses the [RustCrypto](https://github.com/RustCrypto/hashes) collection of libraries, therefore currently supports
* md5
* SHA1
* Whirlpool
* Ripemd160
* Blake2b
* Blake2S
* SHA2-256 (truncated to 224 and 256)
* SHA2-512 (truncated to 224, 256, 384 and 512)
* SHA3 (truncated to 224, 256, 384 and 512)
* Groestl
* Shake (256 and 512 variants)
* Keccak (truncated to 224, 256, 384 and 512)

## Usage
The Keccak algorithm is accessed with the sha3 subcommand.

    USAGE:
        rash [FILE] <SUBCOMMAND>
    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information
    ARGS:
        <FILE>    File to calculate the hash of
    SUBCOMMANDS:
        blake2b      BLAKE2b algorithm
        blake2s      BLAKE2s algorithm
        help         Prints this message or the help of the given subcommand(s)
        md5          md5 algorithm
        ripemd160    Ripemd160 algorithm
        sha1         SHA1 algorithm
        sha2         SHA2 algorithms
        sha3         SHA3 algorithms
        whirlpool    whirlpool algorithm
        
## Install
Via cargo:

    cargo install rash
   
Development version:

    git clone https://github.com/themadprofessor/rash.git && cd rash && cargo install

## Examples
    rash md5 Readme.md
    rash sha3 Readme.md
    rash blake2b -l 64 Readme.md

## Crates used
* [RustCrypto](https://github.com/RustCrypto/hashes)
* [clap](https://crates.io/crates/clap)
* [failure](https://crates.io/crates/failure)
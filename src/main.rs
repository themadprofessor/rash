#[macro_use] extern crate clap;
extern crate failure;
extern crate crypto;

use failure::Error;
use clap::{Arg, SubCommand, AppSettings, ArgMatches};
use crypto::digest::Digest;

use std::io::{Read, BufReader};
use std::fs::File;

fn run() -> Result<(), Error> {
    let matches = args();
    let mut alg: Box<Digest> = get_alg(&matches)?;

    let mut file = BufReader::new(File::open(matches.value_of("FILE").ok_or_else(|| failure::err_msg("missing file"))?)
        .map_err(Error::from)?);
    let mut buf = [0 as u8; 1024];
    loop {
        if file.read(&mut buf)? == 0 {
            break;
        } else {
            alg.input(&buf);
        }
    }
    println!("{}", alg.result_str());

    Ok(())
}

fn args<'a>() -> ArgMatches<'a> {
    app_from_crate!()
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("md5")
            .about("md5 algorithm"))
        .subcommand(SubCommand::with_name("whirlpool")
            .about("whirlpool algorithm"))
        .subcommand(SubCommand::with_name("sha1")
            .about("SHA1 algorithm"))
        .subcommand(SubCommand::with_name("ripemd160")
            .about("Ripemd160 algorithm"))
        .subcommand(SubCommand::with_name("blake2b")
            .about("BLAKE2b algorithm")
            .long_about("BLAKE2b algorithm. Recommended over BLAKE2s on 64bit platforms.")
            .arg(Arg::with_name("len")
                .help("Length of output hash in bytes")
                .long_help("Length of output hash in bytes. Must be between 1 & 64 inclusive.")
                .required(true)))
        .subcommand(SubCommand::with_name("blake2s")
            .about("BLAKE2s algorithm")
            .long_about("BLAKE2s algorithm. Recommended over BLAKE2b on 64bit platforms.")
            .arg(Arg::with_name("len")
                .help("Length of output hash in bytes")
                .long_help("Length of output hash in bytes. Must be between 1 & 32 inclusive.")
                .required(true)))
        .subcommand(SubCommand::with_name("sha2")
            .about("SHA2 algorithms")
            .long_about("SHA2 Algorithms. Supports SHA256 (truncated to 224, 256) and SHA512 (truncated to 224, 256, 384, 512).")
            .arg(Arg::with_name("len")
                .short("l")
                .long("length")
                .help("Length of output hash")
                .long_help("Length of the output hash. Supported lengths with algorithms:\
                \n\talg:\tlen\
                \n\t256:\t224, 256\
                \n\t512:\t224, 256, 384, 512\n")
                .possible_values(&["224", "256", "384", "512"])
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("alg")
                .short("a")
                .long("algorithm")
                .help("SHA2 algorithm")
                .takes_value(true)
                .required(true)
                .possible_values(&["256", "512"])))
        .subcommand(SubCommand::with_name("sha3")
            .about("SHA3 algorithms")
            .arg(Arg::with_name("len")
                .short("l")
                .long("length")
                .help("Length of output help")
                .long_help("Length of the output hash. Supported lengths with algorithms:\
                \n\talg:\tlen
                \n\tsha3:\t244, 256, 384, 512\
                \n\tshake:\t128, 256\
                \n\tkeccak:\t244, 256, 384, 512\n")
                .possible_values(&["128", "244", "256", "384", "512"])
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("alg")
                .short("a")
                .long("algorithm")
                .help("SHA3 Algorithm")
                .long_help("The SHA3 algorithm to use. If not given, sha3 is assumed. See len's help for length algorithm combinations.")
                .takes_value(true)
                .possible_values(&["sha3", "shake", "keccak"])))
        .arg(Arg::with_name("FILE")
            .help("File to calculate the hash of")
            .global(true))
        .get_matches()
}

fn get_alg<'a>(matches: &ArgMatches<'a>) -> Result<Box<Digest>, Error> {
    match matches.subcommand() {
        ("md5", _) => Ok(Box::new(crypto::md5::Md5::new())),
        ("whirlpool", _) => Ok(Box::new(crypto::whirlpool::Whirlpool::new())),
        ("sha1", _) => Ok(Box::new(crypto::sha1::Sha1::new())),
        ("ripemd160", _) => Ok(Box::new(crypto::ripemd160::Ripemd160::new())),
        ("blake2b", Some(matches)) => {
            let len = matches.value_of("len").unwrap().parse().map_err(Error::from)?;
            if len < 1 || len > 64 {
                Err(failure::err_msg("len must be between 1 & 64 inclusive"))
            } else {
                Ok(Box::new(crypto::blake2b::Blake2b::new(len)))
            }
        },
        ("blake2s", Some(matches)) => {
            let len = matches.value_of("len").unwrap().parse().map_err(Error::from)?;
            if len < 1 || len > 32 {
                Err(failure::err_msg("len must be between 1 & 64 inclusive"))
            } else {
                Ok(Box::new(crypto::blake2s::Blake2s::new(len)))
            }
        },
        ("sha2", Some(matches)) => {
            match matches.value_of("alg").unwrap().parse().map_err(Error::from)? {
                256 => match matches.value_of("len").unwrap().parse().map_err(Error::from)? {
                    224 => Ok(Box::new(crypto::sha2::Sha224::new())),
                    256 => Ok(Box::new(crypto::sha2::Sha256::new())),
                    _ => Err(failure::err_msg("invalid length for SHA2-256"))
                },
                512 => match matches.value_of("len").unwrap().parse().map_err(Error::from)? {
                    224 => Ok(Box::new(crypto::sha2::Sha512Trunc224::new())),
                    256 => Ok(Box::new(crypto::sha2::Sha512Trunc256::new())),
                    384 => Ok(Box::new(crypto::sha2::Sha384::new())),
                    512 => Ok(Box::new(crypto::sha2::Sha512::new())),
                    _ => Err(failure::err_msg("invalid length for SHA2-256"))
                },
                _ => Err(failure::err_msg("invalid SHA2 algorithm"))
            }
        },
        ("sha3", Some(matches)) => {
            match matches.value_of("alg").unwrap_or_else(|| "sha3") {
                "sha3" => match matches.value_of("len").unwrap().parse().map_err(Error::from)? {
                    224 => Ok(Box::new(crypto::sha3::Sha3::sha3_224())),
                    256 => Ok(Box::new(crypto::sha3::Sha3::sha3_256())),
                    384 => Ok(Box::new(crypto::sha3::Sha3::sha3_384())),
                    512 => Ok(Box::new(crypto::sha3::Sha3::sha3_512())),
                    _ => Err(failure::err_msg("invalid length for SHA3"))
                },
                "shake" => match matches.value_of("len").unwrap().parse().map_err(Error::from)? {
                    128 => Ok(Box::new(crypto::sha3::Sha3::shake_128())),
                    256 => Ok(Box::new(crypto::sha3::Sha3::shake_256())),
                    _ => Err(failure::err_msg("invalid length for SHAKE"))
                },
                "keccak" => match matches.value_of("len").unwrap().parse().map_err(Error::from)? {
                    224 => Ok(Box::new(crypto::sha3::Sha3::keccak224())),
                    256 => Ok(Box::new(crypto::sha3::Sha3::keccak256())),
                    384 => Ok(Box::new(crypto::sha3::Sha3::keccak384())),
                    512 => Ok(Box::new(crypto::sha3::Sha3::keccak512())),
                    _ => Err(failure::err_msg("invalid length for Keccak"))
                }
                _ => Err(failure::err_msg("invalid SHA3 algorithm"))
            }
        },
        _ => Err(failure::err_msg("unknown algorithm"))
    }
}

fn main() {
    match run() {
        Ok(_) => {},
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1)
        }
    }
}
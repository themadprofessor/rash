use assert_cli::Assert;

macro_rules! test_file {
    ($name: ident, $arg: expr, $hash: expr, $file: expr, $extra_args: expr) => {
        #[test]
        fn $name() {
            use std::iter;
            Assert::main_binary()
                .with_args(&iter::once(&$arg).chain($extra_args.iter()).chain(iter::once(&$file)).collect::<Vec<_>>())
                .stdout().is($hash)
                .unwrap()
        }
    };
    ($name: ident, $arg: expr, $hash: expr, $file: expr) => {
        #[test]
        fn $name() {
            Assert::main_binary()
                .with_args(&[$arg, $file])
                .stdout().is($hash)
                .unwrap()
        }
    };
}

macro_rules! test_alg {
    ($args: expr, $alg: ident, $([$name: ident, $hash: expr, $file: expr]),*) => {
    mod $alg {
        use assert_cli::Assert;
    $(
        test_file!($name, $args, $hash, $file);
    )*
    }
    };
    ($args: expr, $alg: ident, $extra_arg: expr, $([$name: ident, $hash: expr, $file: expr]),*) => {
    mod $alg {
        use assert_cli::Assert;
    $(
        test_file!($name, $args, $hash, $file, $extra_arg);
    )*
    }
    };
}

#[test]
fn no_args() {
    Assert::main_binary()
        .fails()
        .unwrap()
}

#[test]
fn unknown_alg() {
    Assert::main_binary()
        .with_args(&["NOT_REAL_ALG"])
        .fails()
        .unwrap()
}

test_alg!("md5", md5,
    [empty_file, "d41d8cd98f00b204e9800998ecf8427e", "test_data/empty.dat"]
);

test_alg!("sha1", sha1,
    [empty_file, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "test_data/empty.dat"]
);

test_alg!("whirlpool", whirlpool,
    [empty_file, "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3", "test_data/empty.dat"]
);

test_alg!("blake2b", blake2b,
    [empty_file, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", "test_data/empty.dat"]
);

test_alg!("ripemd160", ripemd160,
    [empty_file, "9c1185a5c5e9fc54612808977ee8f548b2258d31", "test_data/empty.dat"]
);

test_alg!("sha3", sha3,
    [empty_file, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", "test_data/empty.dat"]
);

test_alg!("sha3", keccak, ["-a", "keccak"],
    [empty_file, "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", "test_data/empty.dat"]
);

test_alg!("sha2", sha512,
    [empty_file, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "test_data/empty.dat"]
);

test_alg!("sha2", sha256, ["-a", "256"],
    [empty_file, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "test_data/empty.dat"]
);
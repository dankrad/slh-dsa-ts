//! Reproducible fixtures from the pinned reference's default (no optional
//! hardware/platform features) public API. No reference file is modified.
use serde_json::{json, Value};

const PIN: &str = "462724e2b5f8ffe63a2ce76c9b1ab07099c1807b";
fn bytes(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 113 + salt) & 255) as u8).collect()
}
fn h(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}
macro_rules! fixture {
    ($module:ident, $name:literal, $length:expr, $salt:expr, $ctx:expr) => {{
        use slhdsa::$module as s;
        const N: usize = s::params::N;
        let a: [u8; N] = bytes(N, $salt).try_into().unwrap();
        let b: [u8; N] = bytes(N, $salt + 31).try_into().unwrap();
        let c: [u8; N] = bytes(N, $salt + 67).try_into().unwrap();
        let rand: [u8; N] = bytes(N, $salt + 97).try_into().unwrap();
        let (sk, pk) = s::slh_keygen_internal(&a, &b, &c);
        let message = bytes($length, $salt + 7);
        let context = bytes($ctx, $salt + 11);
        let internal = s::slh_sign_internal(&message, &sk, &rand);
        let external = s::slh_sign(&message, &context, &sk, &rand).unwrap();
        assert!(s::slh_verify_internal(&message, &internal, &pk));
        assert!(s::slh_verify(&message, &external, &context, &pk));
        let mut bad = internal.clone(); bad[N] ^= 1;
        assert!(!s::slh_verify_internal(&message, &bad, &pk));
        json!({"name": $name, "skSeed": hex::encode(a), "skPrf": hex::encode(b),
            "pkSeed": hex::encode(c), "publicKey": hex::encode(pk), "secretKey": hex::encode(sk),
            "message": hex::encode(message), "context": hex::encode(context),
            "randomness": hex::encode(rand), "internalSignature": hex::encode(internal),
            "externalSignature": hex::encode(external)})
    }};
}
macro_rules! verify_case {
    ($module:ident, $case:expr) => {{
        use slhdsa::$module as s;
        let c = $case;
        let pk: [u8; s::params::PK_BYTES] = h(c, "publicKey").try_into().unwrap();
        let message = h(c, "message"); let context = h(c, "context");
        assert!(s::slh_verify_internal(&message, &h(c,"internalSignature"), &pk));
        assert!(s::slh_verify(&message, &h(c,"externalSignature"), &context, &pk));
    }};
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("verify") {
        let input: Value = serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
        let cases = input["cases"].as_array().unwrap();
        for c in cases {
            match c["name"].as_str().unwrap() {
                "SLH-DSA-SHA2-128s" => verify_case!(sha2_128s, c),
                "SLH-DSA-SHA2-128f" => verify_case!(sha2_128f, c),
                "SLH-DSA-SHA2-192s" => verify_case!(sha2_192s, c),
                "SLH-DSA-SHA2-192f" => verify_case!(sha2_192f, c),
                "SLH-DSA-SHA2-256s" => verify_case!(sha2_256s, c),
                "SLH-DSA-SHA2-256f" => verify_case!(sha2_256f, c),
                "SLH-DSA-SHAKE-128s" => verify_case!(shake_128s, c),
                "SLH-DSA-SHAKE-128f" => verify_case!(shake_128f, c),
                "SLH-DSA-SHAKE-192s" => verify_case!(shake_192s, c),
                "SLH-DSA-SHAKE-192f" => verify_case!(shake_192f, c),
                "SLH-DSA-SHAKE-256s" => verify_case!(shake_256s, c),
                "SLH-DSA-SHAKE-256f" => verify_case!(shake_256f, c),
                unknown => panic!("unknown parameter set {unknown}"),
            }
        }
        println!("Rust verified {} TypeScript signatures (internal + external, all twelve sets)", cases.len() * 2);
    } else {
        let cases = vec![
            fixture!(sha2_128s, "SLH-DSA-SHA2-128s", 0, 1, 0),
            fixture!(sha2_128f, "SLH-DSA-SHA2-128f", 1, 2, 1),
            fixture!(sha2_192s, "SLH-DSA-SHA2-192s", 55, 3, 255),
            fixture!(sha2_192f, "SLH-DSA-SHA2-192f", 56, 4, 254),
            fixture!(sha2_256s, "SLH-DSA-SHA2-256s", 63, 5, 2),
            fixture!(sha2_256f, "SLH-DSA-SHA2-256f", 64, 6, 0),
            fixture!(shake_128s, "SLH-DSA-SHAKE-128s", 111, 7, 255),
            fixture!(shake_128f, "SLH-DSA-SHAKE-128f", 112, 8, 1),
            fixture!(shake_192s, "SLH-DSA-SHAKE-192s", 127, 9, 2),
            fixture!(shake_192f, "SLH-DSA-SHAKE-192f", 128, 10, 0),
            fixture!(shake_256s, "SLH-DSA-SHAKE-256s", 136, 11, 255),
            fixture!(shake_256f, "SLH-DSA-SHAKE-256f", 1025, 12, 254),
        ];
        println!("{}", serde_json::to_string_pretty(&json!({
            "source": "danrobinson/rust-pq", "commit": PIN,
            "api": "slhdsa default/no optional features", "cases": cases
        })).unwrap());
    }
}

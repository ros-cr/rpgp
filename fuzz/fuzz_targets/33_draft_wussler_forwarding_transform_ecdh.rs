#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::packet::PublicKeyEncryptedSessionKey;

use pgp::composed::DecryptionOptions;
use pgp::composed::TheRing;
use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::Password,
};

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    proxy_param: [u8; 32],
    eph: [u8; 32],
}

fuzz_target!(|data: Input| {
    // related to
    // <https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-message-transformation>

    // simple fuzzer test, requires target function visibility changed to `pub`
    // no interesting behavior so far
    let _ = PublicKeyEncryptedSessionKey::transform_ecdh_ephemeral(
        data.eph.try_into().unwrap(),
        data.proxy_param.into(),
    );
});

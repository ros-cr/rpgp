#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::DecryptionOptions;
use pgp::composed::TheRing;
use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::Password,
};

fuzz_target!(|data: &[u8]| {
    let message_res = Message::from_bytes(data);

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok(message) => {
            #[cfg(feature = "fuzzer_verbose1")]
            println!("message: {:?}", message);

            // we're interested in the message flow for encrypted messages
            // otherwise bail early
            if !message.is_encrypted() {
                return;
            }

            // included here to avoid I/O operations
            let key_input = include_str!(
                "../../tests/draft-bre-openpgp-samples-00/bob.sec.asc"
            );

            // this only needs to be done once on init
            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();

            // let pw = Password::from("password");
            let pw = Password::empty();

            let ring = TheRing {
                message_password: vec![&pw],
                secret_keys: vec![&decrypt_key],
                decrypt_options: DecryptionOptions::new().enable_draft_forwarding(),
                ..Default::default()
            };
            

            let _ = message.decrypt_the_ring(ring, true);
            //     Ok(dec)
            // };

            // match decryption_res {
            //     // the fuzzer is not clever enough to encrypt anything to the public key
            //     // so any "successful" decryption is likely a bug and report-worthy
            //     Ok(_decryption) => panic!("potential fake decryption, investigate input"),
            //     // not interesting
            //     Err(_) => {}
            // }
        }
    }
});

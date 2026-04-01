#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::packet::SecretSubkey;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    one: [u8; 32],
    two: [u8; 32],
}

// NOTE: at the moment, this harness is not very interesting
fuzz_target!(|data: Input| {
    // requires the `compute_proxy_parameter()` visibility changed to `pub`
    let res = SecretSubkey::compute_proxy_parameter(data.one, data.two);

    match res {
        Err(_err) => {
            #[cfg(feature = "fuzzer_verbose1")]
            println!("error: {:?}", _err);
        }
        Ok(_ok) => {
            // typical case
            #[cfg(feature = "fuzzer_verbose1")]
            println!("succeeded: {:?}", _ok.as_ref());
        }
    }
});

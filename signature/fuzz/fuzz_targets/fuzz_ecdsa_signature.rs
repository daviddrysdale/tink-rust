#![no_main]
use libfuzzer_sys::fuzz_target;
use std::{cell::RefCell, sync::Once};

thread_local! {
    static INIT: Once = Once::new();
    static VERIFIER: RefCell<Option<Box<dyn tink::Verifier>>> = RefCell::new(None);
}

fn get_verifier() -> Box<dyn tink::Verifier> {
    INIT.with(|i| {
        i.call_once(|| {
            tink_signature::init();
            let kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
            let pubkh = kh.public().unwrap();
            let verifier = tink_signature::new_verifier(&pubkh).unwrap();
            VERIFIER.with(|v| *(v.borrow_mut()) = Some(verifier));
        })
    });
    VERIFIER.with(|v| v.borrow().as_ref().unwrap().box_clone())
}

fuzz_target!(|data: &[u8]| {
    let _ = get_verifier().verify(data, b"this data needs to be signed");
});

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    bxplore::fuzzing::resource_previews(data);
});

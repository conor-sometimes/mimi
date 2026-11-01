#![no_main]
use libfuzzer_sys::fuzz_target;

// The only userspace `unsafe` is parse()'s read_unaligned of ring-buffer bytes, so fuzz it hard: any
// byte sequence must parse to None or a Lineage and render without panicking or UB. When the input
// is at least a full record the resulting Lineage is arbitrary, so this also fuzzes the renderers on
// arbitrary field values -- banken's "a hostile record degrades a detection, never crashes" bar.
fuzz_target!(|data: &[u8]| {
    if let Some(lin) = mimi_types::parse(data) {
        let _ = mimi_types::render_json(&lin);
        let _ = mimi_types::render_text(&lin);
    }
});

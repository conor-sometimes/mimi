//! A tiny read-only BTF parser, just enough to look up a struct member's byte offset in the running
//! kernel's own type information (/sys/kernel/btf/vmlinux). It is how mimi does CO-RE: the loader
//! resolves the task_struct/mm_struct field offsets for the kernel it is about to run on and writes
//! them into the probe's OFFSETS map, so the probe carries no offset of its own and one binary adapts
//! to each kernel's layout instead of assuming the build kernel's.
//!
//! This is deliberately not a general BTF library and adds no dependency: it walks the type section
//! once, skipping each type's kind-specific payload, and reads the members of the two structs it is
//! asked about. aya cannot yet emit BTF relocations from Rust (aya-rs/aya#349) and does not expose
//! BTF member offsets through its public API, hence this small local reader does the resolution in
//! userspace at load.

use std::collections::HashMap;

const BTF_MAGIC: u16 = 0xeb9f;
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;

fn rd_u32(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("BTF truncated at offset {off}"))
}

fn rd_u16(b: &[u8], off: usize) -> Result<u16, String> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("BTF truncated at offset {off}"))
}

// Bytes the kind-specific payload of a type occupies after the 12-byte common header, so the walk
// can step to the next type. Unknown kinds are an error, never a guessed length, so a future kind
// can never silently misalign the walk and yield a wrong offset.
fn payload_len(kind: u32, vlen: u32) -> Result<usize, String> {
    let v = vlen as usize;
    Ok(match kind {
        KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
        KIND_ARRAY => 12,
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => v * 12,
        KIND_ENUM | KIND_FUNC_PROTO => v * 8,
        2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0, // PTR,FWD,TYPEDEF,VOLATILE,CONST,RESTRICT,FUNC,FLOAT,TYPE_TAG
        other => return Err(format!("BTF: unhandled type kind {other}")),
    })
}

// One parsed type, enough to resolve struct member offsets. Index i in the Vec is BTF type id i+1
// (id 0 is void). Only struct/union carry members; other kinds keep name/kind to resolve references.
struct Ty {
    name: String,
    kind: u32,
    kind_flag: bool,
    members: Vec<(String, u32, u32)>, // (name, member type id, raw offset word)
}

/// members maps "struct_name" -> ("field_name" -> byte offset) for the named structs, read from a
/// raw BTF blob (native-endian, as the kernel exposes it). Anonymous struct/union members are
/// flattened: a field inside an unnamed nested struct (as mm_struct holds arg_start/arg_end) is
/// reported at its absolute byte offset within the outer struct, matching pahole.
pub fn member_offsets(
    btf: &[u8],
    wanted: &[&str],
) -> Result<HashMap<String, HashMap<String, u32>>, String> {
    if rd_u16(btf, 0)? != BTF_MAGIC {
        return Err("not BTF (bad magic)".into());
    }
    // btf_header: magic u16, version u8, flags u8, hdr_len u32, type_off u32, type_len u32,
    // str_off u32, str_len u32. Section offsets are relative to the end of the header.
    let hdr_len = rd_u32(btf, 4)? as usize;
    let type_off = hdr_len + rd_u32(btf, 8)? as usize;
    let type_len = rd_u32(btf, 12)? as usize;
    let str_off = hdr_len + rd_u32(btf, 16)? as usize;
    let str_len = rd_u32(btf, 20)? as usize;
    let strs = btf
        .get(str_off..str_off + str_len)
        .ok_or("BTF string section out of range")?;

    let name_at = |off: u32| -> String {
        let s = off as usize;
        match strs.get(s..) {
            Some(rest) => {
                let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                String::from_utf8_lossy(&rest[..end]).into_owned()
            }
            None => String::new(),
        }
    };

    // First pass: index every type by id, so a member's type can be followed (to flatten anonymous
    // nested structs). Type ids are 1-based; types[0] is id 1.
    let mut types: Vec<Ty> = Vec::new();
    let type_end = type_off + type_len;
    let mut pos = type_off;
    while pos + 12 <= type_end {
        let name_off = rd_u32(btf, pos)?;
        let info = rd_u32(btf, pos + 4)?;
        let vlen = info & 0xffff;
        let kind = (info >> 24) & 0x1f;
        let kind_flag = (info >> 31) & 1 == 1;
        let body = pos + 12;
        let plen = payload_len(kind, vlen)?;
        if body + plen > btf.len() {
            return Err("BTF type payload out of range".into());
        }
        let mut members = Vec::new();
        if kind == KIND_STRUCT || kind == KIND_UNION {
            for i in 0..vlen as usize {
                let m = body + i * 12;
                members.push((
                    name_at(rd_u32(btf, m)?),
                    rd_u32(btf, m + 4)?,
                    rd_u32(btf, m + 8)?,
                ));
            }
        }
        types.push(Ty {
            name: name_at(name_off),
            kind,
            kind_flag,
            members,
        });
        pos = body + plen;
    }

    let want: std::collections::HashSet<&str> = wanted.iter().copied().collect();
    let mut out: HashMap<String, HashMap<String, u32>> = HashMap::new();
    for (i, t) in types.iter().enumerate() {
        if (t.kind == KIND_STRUCT || t.kind == KIND_UNION) && want.contains(t.name.as_str()) {
            let mut fields = HashMap::new();
            flatten(&types, i, 0, &mut fields);
            out.insert(t.name.clone(), fields);
        }
    }
    Ok(out)
}

// flatten records every named field of the struct at type-index `idx` into `fields` at its byte
// offset, adding `base_bits` (the offset of this struct within its outer struct). An unnamed
// struct/union member is descended into so its fields surface at their absolute offset.
fn flatten(types: &[Ty], idx: usize, base_bits: u32, fields: &mut HashMap<String, u32>) {
    let t = &types[idx];
    for (mname, mtype, moff) in &t.members {
        // With kind_flag the low 24 bits are the bit offset (high 8 a bitfield size); otherwise the
        // whole word is the bit offset.
        let bit = base_bits
            + if t.kind_flag {
                moff & 0x00ff_ffff
            } else {
                *moff
            };
        if mname.is_empty() {
            if let Some(child) = (*mtype as usize).checked_sub(1).and_then(|j| types.get(j))
                && (child.kind == KIND_STRUCT || child.kind == KIND_UNION)
            {
                flatten(types, *mtype as usize - 1, bit, fields);
            }
        } else {
            fields.entry(mname.clone()).or_insert(bit / 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hand-built BTF blob: one INT, then struct S { a @ byte 8; b @ byte 24; }. Exercises the
    // header maths, the string table, the type walk past a non-struct, and member-offset decoding,
    // with no kernel needed.
    fn synth_btf() -> Vec<u8> {
        // strings: "\0" "int\0" "S\0" "a\0" "b\0"
        let mut strs = vec![0u8];
        let mut soff = |s: &mut Vec<u8>, w: &str| -> u32 {
            let at = s.len() as u32;
            s.extend_from_slice(w.as_bytes());
            s.push(0);
            at
        };
        let n_int = soff(&mut strs, "int");
        let n_s = soff(&mut strs, "S");
        let n_a = soff(&mut strs, "a");
        let n_b = soff(&mut strs, "b");

        let mut types = Vec::new();
        let push_u32 = |t: &mut Vec<u8>, v: u32| t.extend_from_slice(&v.to_le_bytes());
        // type 1: INT "int", size 4
        push_u32(&mut types, n_int);
        push_u32(&mut types, (KIND_INT << 24) | 0);
        push_u32(&mut types, 4);
        push_u32(&mut types, 4); // int_data (encoding/bits), unused by us
        // type 2: STRUCT "S", vlen 2, size 32, members a@64bit b@192bit
        push_u32(&mut types, n_s);
        push_u32(&mut types, (KIND_STRUCT << 24) | 2);
        push_u32(&mut types, 32);
        push_u32(&mut types, n_a);
        push_u32(&mut types, 1); // type id of int
        push_u32(&mut types, 64); // bit offset -> byte 8
        push_u32(&mut types, n_b);
        push_u32(&mut types, 1);
        push_u32(&mut types, 192); // bit offset -> byte 24

        let mut btf = Vec::new();
        let push_u32b = |t: &mut Vec<u8>, v: u32| t.extend_from_slice(&v.to_le_bytes());
        btf.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        btf.push(1); // version
        btf.push(0); // flags
        push_u32b(&mut btf, 24); // hdr_len
        push_u32b(&mut btf, 0); // type_off
        push_u32b(&mut btf, types.len() as u32);
        push_u32b(&mut btf, types.len() as u32); // str_off
        push_u32b(&mut btf, strs.len() as u32);
        btf.extend_from_slice(&types);
        btf.extend_from_slice(&strs);
        btf
    }

    #[test]
    fn decodes_member_byte_offsets() {
        let btf = synth_btf();
        let got = member_offsets(&btf, &["S"]).expect("parse synthetic BTF");
        let s = got.get("S").expect("found struct S");
        assert_eq!(s.get("a"), Some(&8));
        assert_eq!(s.get("b"), Some(&24));
    }

    #[test]
    fn rejects_non_btf() {
        assert!(member_offsets(b"not btf at all", &["S"]).is_err());
    }

    // On a BTF-capable kernel, the real type information resolves to plausible offsets for the
    // fields the probe reads. It asserts shape, not exact values (those are per-kernel), so it runs
    // on any kernel; a build host without BTF simply skips it.
    // Opt-in (cargo test -- --ignored): on the build kernel every compiled offset must equal the
    // kernel's own BTF, i.e. the loader's validate_offsets would find no mismatch. Ignored by
    // default because it only holds on a kernel with the build kernel's layout -- it is exactly how
    // a build host confirms the hardcoded offsets before shipping, and proves this parser against
    // ground truth (pahole agrees: tgid 1924, real_parent 1936, comm 2464, mm 1792; mm_struct
    // arg_start 488, arg_end 496 on 6.18.59).
    #[test]
    #[ignore = "build-kernel specific; run with --ignored to confirm the compiled offsets"]
    fn live_offsets_match_compiled() {
        let data = std::fs::read("/sys/kernel/btf/vmlinux").expect("kernel BTF");
        let got = member_offsets(&data, &["task_struct", "mm_struct"]).expect("parse live BTF");
        for (st, field, want) in mimi_types::OFFSET_TABLE {
            let g = got.get(st).and_then(|m| m.get(field)).copied();
            assert_eq!(
                g,
                Some(want),
                "{st}.{field}: kernel {g:?} vs compiled {want}"
            );
        }
    }

    #[test]
    fn resolves_plausible_offsets_from_live_kernel() {
        let Ok(data) = std::fs::read("/sys/kernel/btf/vmlinux") else {
            return;
        };
        let got = member_offsets(&data, &["task_struct", "mm_struct"]).expect("parse live BTF");
        let ts = got.get("task_struct").expect("task_struct present");
        for f in ["tgid", "real_parent", "comm", "mm"] {
            let off = *ts
                .get(f)
                .unwrap_or_else(|| panic!("task_struct.{f} present"));
            assert!(
                off > 0 && off < 1 << 20,
                "task_struct.{f} offset {off} implausible"
            );
        }
        let mm = got.get("mm_struct").expect("mm_struct present");
        let (start, end) = (mm["arg_start"], mm["arg_end"]);
        assert!(
            start > 0 && end == start + 8,
            "mm arg_start/arg_end {start}/{end} implausible"
        );
    }
}

//! Pure hardening engine shared by the C ABI (`lib.rs`) and the CLI (`main.rs`).
//!
//! Every transform is append-only: the caller's bytes are copied verbatim and
//! a blob is appended after an 8-byte alignment pad, so PE / ELF / Mach-O
//! loaders keep seeing the original image.  Determinism is a hard requirement:
//! the same `(input, seed, intensity)` always yields the same output bytes,
//! which is the attestable-build primitive carried across the FFI boundary.
//!
//! Concept inspired by: Anchor — zero-dependency native kernel, C-ABI surface

/// Version banner returned by the C ABI and the CLI.
pub const VERSION: &str = "umbra-native 0.1.0 (rust)";

/// Marker written by [`poison`] as the head of its appended payload and again
/// in the trailer that marks an already-poisoned artifact.
pub const CANARY_MARKER: &[u8] = b"umbra:canary";

/// Marker written by [`exhaust`] as the head of its appended payload and again
/// in the trailer that marks an already-padded artifact.
pub const EXHAUST_MARKER: &[u8] = b"umbra:_umbra_padding";

/// Executable container families the kernel accepts. Anything else is refused
/// so we never append garbage to an unrecognised format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Pe,
    Elf,
    MachO,
}

const MACHO_MAGICS: [[u8; 4]; 6] = [
    [0xFE, 0xED, 0xFA, 0xCE], // big-endian 32-bit
    [0xCE, 0xFA, 0xED, 0xFE], // little-endian 32-bit
    [0xFE, 0xED, 0xFA, 0xCF], // big-endian 64-bit
    [0xCF, 0xFA, 0xED, 0xFE], // little-endian 64-bit
    [0xCA, 0xFE, 0xBA, 0xBE], // fat binary, big-endian
    [0xBE, 0xBA, 0xFE, 0xCA], // fat binary, little-endian
];

const KEY_PREFIXES: [&str; 5] = ["sk_live_", "pk_live_", "xoxb-", "ghp_", "AKIA"];
const KEY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const FILLER_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/// Detect PE, ELF and (thin or fat) Mach-O by leading magic.
pub fn detect_container(data: &[u8]) -> Option<Container> {
    if data.starts_with(b"MZ") {
        return Some(Container::Pe);
    }
    if data.starts_with(b"\x7fELF") {
        return Some(Container::Elf);
    }
    if data.len() >= 4 && MACHO_MAGICS.iter().any(|magic| data.starts_with(magic)) {
        return Some(Container::MachO);
    }
    None
}

/// xorshift64* — small, dependency-free, and fully deterministic.
///
/// The state must never be zero (xorshift would stay there), so a zero seed is
/// remapped to the 64-bit golden-ratio constant.
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Unbiased-enough bounded draw; `upper == 0` yields 0 instead of panicking.
    pub fn below(&mut self, upper: u32) -> u32 {
        if upper == 0 {
            0
        } else {
            self.next_u32() % upper
        }
    }
}

/// Quantity ladder shared by both strategies: 8 / 64 / 256 / 1024.
///
/// `0 = stealth`, `1 = balanced`, `2 = maximum`, `3 = bankrupt`; unknown values
/// fall back to balanced so a bad flag can never disable the transform.
pub fn density_for_intensity(intensity: u32) -> usize {
    match intensity {
        0 => 8,
        1 => 64,
        2 => 256,
        3 => 1024,
        _ => 64,
    }
}

/// FNV-1a (64-bit) over `bytes` — the integrity tag carried by the
/// idempotence trailer.
///
/// This is a cheap structural checksum, not a cryptographic primitive: its
/// only job is to tell a trailer this module actually wrote apart from an
/// accidental or hand-pasted marker line.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Append the self-describing trailer that marks a hardened artifact.
///
/// Layout (ASCII, at the very end of the file):
///
/// ```text
/// \n<marker>:<payload_len>:<fnv1a64(payload) as 16 lowercase hex>\n
/// ```
///
/// `<payload_len>` is the byte length of the blob appended after the original
/// input.  The leading `\n` keeps the marker on its own line even when the
/// payload does not end with one.
fn append_trailer(out: &mut Vec<u8>, marker: &[u8], payload: &[u8]) {
    out.push(b'\n');
    out.extend_from_slice(marker);
    out.push(b':');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(format!("{:016x}", fnv1a64(payload)).as_bytes());
    out.push(b'\n');
}

/// Rightmost index of `needle` in `haystack`, if any.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&start| &haystack[start..start + needle.len()] == needle)
}

/// True when `data` ends with a well-formed trailer written by
/// [`append_trailer`].
///
/// The marker only counts where this module puts it: as the last line of the
/// file, preceded on the same line by the length of the payload and that
/// payload's FNV-1a tag.  A bare occurrence of the marker — in a comment,
/// inside a string literal, or baked into an unrelated binary — therefore no
/// longer suppresses hardening; only a structurally complete trailer does.
///
/// This is an idempotence check, not proof of authenticity: anyone able to
/// rewrite the artifact can also rewrite the trailer.
fn has_trailer(data: &[u8], marker: &[u8]) -> bool {
    if !data.ends_with(b"\n") {
        return false;
    }
    let body_end = data.len() - 1;
    let mut needle: Vec<u8> = Vec::with_capacity(marker.len() + 2);
    needle.push(b'\n');
    needle.extend_from_slice(marker);
    needle.push(b':');
    let Some(pos) = rfind(&data[..body_end], &needle) else {
        return false;
    };
    let rest = &data[pos + needle.len()..body_end];
    let Some(colon) = rest.iter().position(|&b| b == b':') else {
        return false;
    };
    let (len_field, tag_field) = (&rest[..colon], &rest[colon + 1..]);
    if len_field.is_empty() || len_field.len() > 20 {
        return false;
    }
    if !len_field.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if tag_field.len() != 16 {
        return false;
    }
    let Ok(len_text) = std::str::from_utf8(len_field) else {
        return false;
    };
    let Ok(payload_len) = len_text.parse::<usize>() else {
        return false;
    };
    let mut expected: u64 = 0;
    for &byte in tag_field {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return false,
        };
        expected = (expected << 4) | u64::from(digit);
    }
    if payload_len < marker.len() || payload_len > pos {
        return false;
    }
    fnv1a64(&data[pos - payload_len..pos]) == expected
}

fn aligned_pad(len: usize) -> usize {
    (8 - (len % 8)) % 8
}

/// Append a deterministic canary table: an ASCII marker plus intensity-scaled
/// decoy credentials built from a seeded PRNG.  Never rewrites input bytes.
pub fn poison(input: &[u8], seed: u64, intensity: u32) -> Option<Vec<u8>> {
    detect_container(input)?;
    if has_trailer(input, CANARY_MARKER) {
        // Idempotence: the caller sees byte-identical output and skips the write.
        return Some(input.to_vec());
    }

    let mut rng = XorShift64::new(seed);
    let entries = density_for_intensity(intensity);
    let pad = aligned_pad(input.len());

    let mut payload: Vec<u8> = Vec::with_capacity(pad + 32 + entries * 64);
    for _ in 0..pad {
        payload.push(rng.next_u32() as u8);
    }
    payload.extend_from_slice(CANARY_MARKER);
    payload.push(b'\n');

    for index in 0..entries {
        payload.extend_from_slice(format!("umbra:canary:{:04}: ", index).as_bytes());
        let prefix = KEY_PREFIXES[rng.below(KEY_PREFIXES.len() as u32) as usize];
        payload.extend_from_slice(prefix.as_bytes());
        let body_len = 24 + rng.below(17) as usize; // 24..=40 characters
        let alphabet: &[u8] = if prefix == "AKIA" {
            BASE32_ALPHABET
        } else {
            KEY_ALPHABET
        };
        for _ in 0..body_len {
            payload.push(alphabet[rng.below(alphabet.len() as u32) as usize]);
        }
        payload.push(b'\n');
    }

    let mut out = Vec::with_capacity(input.len() + payload.len() + 64);
    out.extend_from_slice(input);
    out.extend_from_slice(&payload);
    append_trailer(&mut out, CANARY_MARKER, &payload);
    Some(out)
}

/// Append dead weight: a marker plus `density * 1024` bytes of seeded,
/// base64-shaped filler.  Parsers and LLM context windows still ingest every
/// byte; the executable never references it.
pub fn exhaust(input: &[u8], seed: u64, intensity: u32) -> Option<Vec<u8>> {
    detect_container(input)?;
    if has_trailer(input, EXHAUST_MARKER) {
        return Some(input.to_vec());
    }

    let mut rng = XorShift64::new(seed);
    let density_kib = density_for_intensity(intensity);
    let filler_len = density_kib * 1024;
    let pad = aligned_pad(input.len());

    let mut payload: Vec<u8> = Vec::with_capacity(pad + 32 + filler_len + filler_len / 76 + 1);
    for _ in 0..pad {
        payload.push(rng.next_u32() as u8);
    }
    payload.extend_from_slice(EXHAUST_MARKER);
    payload.push(b'\n');

    for index in 0..filler_len {
        if index > 0 && index % 76 == 0 {
            payload.push(b'\n');
        }
        payload.push(FILLER_ALPHABET[rng.below(FILLER_ALPHABET.len() as u32) as usize]);
    }
    payload.push(b'\n');

    let mut out = Vec::with_capacity(input.len() + payload.len() + 64);
    out.extend_from_slice(input);
    out.extend_from_slice(&payload);
    append_trailer(&mut out, EXHAUST_MARKER, &payload);
    Some(out)
}

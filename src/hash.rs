use sha2::{Digest, Sha256};

use crate::N;

const PADDING_F: u8 = 0;
const PADDING_PRF: u8 = 3;

fn core_hash(input: &[u8]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.input(input);
    hasher.result().into()
}

/// Compute pseudorandom function PRF(key, input), for a key of params->n bytes, and a 32-byte input.
pub fn prf(key: &[u8; N], input: &[u8; 32]) -> [u8; N] {
    let mut buf = [0u8; 2 * N + 32];

    for i in 0..N {
        buf[i] = PADDING_PRF;
    }

    for i in 0..N {
        buf[N + i] = key[i];
    }

    for i in 0..32 {
        buf[N * 2 + i] = input[i];
    }

    core_hash(&buf)
}

/// Keyed hash function
pub fn hash_f(key: &[u8; N], input: &[u8; N]) -> [u8; N] {
    let mut buf = [0u8; 3 * N];

    for i in 0..N {
        buf[i] = PADDING_F;
    }

    for i in 0..N {
        buf[N + i] = key[i];
    }

    for i in 0..32 {
        buf[N * 2 + i] = input[i];
    }

    core_hash(&buf)
}

#[cfg(feature = "WOTSP-SHA2_256")]
use sha2::{Digest, Sha256};
#[cfg(feature = "WOTSP-SHA2_512")]
use sha2::{Digest, Sha512};

use crate::N;

const PADDING_F: usize = 0;
const PADDING_PRF: usize = 3;

fn core_hash(input: &[u8]) -> [u8; N] {
    #[cfg(feature = "WOTSP-SHA2_256")]
    let mut hasher = Sha256::new();
    #[cfg(feature = "WOTSP-SHA2_512")]
    let mut hasher = Sha512::new();

    hasher.input(input);
    hasher.result().into()
}

/// Compute pseudorandom function PRF(key, input), for a key of params->n bytes, and a 32-byte input.
pub(crate) fn prf(key: &[u8; N], input: &[u8; 32]) -> [u8; N] {
    let mut buf = [0u8; 2 * N + 32];

    byte_array(&mut buf[0..N], PADDING_PRF);

    for i in 0..N {
        buf[N + i] = key[i];
    }

    for i in 0..32 {
        buf[N * 2 + i] = input[i];
    }

    core_hash(&buf)
}

/// Keyed hash function
pub(crate) fn hash_f(key: &[u8; N], input: &[u8; N]) -> [u8; N] {
    let mut buf = [0u8; 3 * N];

    byte_array(&mut buf[0..N], PADDING_F);

    for i in 0..N {
        buf[N + i] = key[i];
    }

    for i in 0..32 {
        buf[N * 2 + i] = input[i];
    }

    core_hash(&buf)
}

pub(crate) fn byte_array(output: &mut [u8], mut input: usize) {
    for i in (0..output.len()).rev() {
        output[i] = (input & 0xff) as u8;
        input = input >> 8;
    }
}

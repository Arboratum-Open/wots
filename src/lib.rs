//#![no_std]
#![deny(unused_extern_crates)]
#![warn(
    //missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! Winternitz One Time Signature Scheme (W-OTS+)

use rand;

mod hash;
use hash::{byte_array, hash_f, prf};

/// The message length as well as the length of a private key, public key, or signature element in bytes.
const N: usize = 32;
/// The Winternitz parameter; it is a member of the set {4, 16}.
const W: usize = 16;
const LOG_W: usize = 4;
/// L1 = ceil(8N / lg(W))
const L1: usize = 64;
/// L2 = floor(lg(L1 * (W - 1)) / lg(W)) + 1
const L2: usize = 3;
/// The number of N-byte string elements in a WOTS+ private key, public key, and signature.
const LEN: usize = L1 + L2;

/// The key seed for both secrey key and public key
#[derive(Clone, Copy, Default, Debug)]
pub struct Seed([u8; N]);

impl Seed {
    /// Generate a random seed
    pub fn new() -> Self {
        Self(rand::random())
    }
}

/// The address to randomize each hash function call to prevent multi-target attacks on the used hash function.
#[derive(Clone, Copy, Default, Debug)]
pub struct Adrs([u8; 32]);

impl Adrs {
    /// Generate a random address
    pub fn new() -> Self {
        Self(rand::random())
    }

    /// Set the chain field of a WOTS+ address to the given value.
    pub fn set_chain(&mut self, b: u32) {
        byte_array(&mut self.0[20..24], b as usize);
    }

    /// Set the hash field of a WOTS+ address to the given value.
    pub fn set_hash(&mut self, b: u32) {
        byte_array(&mut self.0[24..28], b as usize);
    }

    /// Set the keymask field of a WOTS+ address to the given value.
    pub fn set_keymask(&mut self, b: u32) {
        byte_array(&mut self.0[28..32], b as usize);
    }
}

/// WOTS+ private key that hasn't expanded yet. It contain a seed to derive and an address for the key pair
#[derive(Clone, Default, Debug)]
pub struct SecKey {
    seed: Seed,
    address: Adrs,
}

/// WOTS+ signature
#[derive(Clone, Copy)]
pub struct Signature {
    inner: [u8; N * LEN],
    pub_seed: Seed,
    address: Adrs,
}

impl SecKey {
    /// Generate a random secret key
    pub fn new() -> Self {
        Self {
            seed: Seed::new(),
            address: Adrs::new(),
        }
    }

    /// Set the seed of secret key
    pub fn set_seed(&mut self, seed: Seed) {
        self.seed = seed;
    }

    /// Set the address of secret key
    pub fn set_address(&mut self, address: Adrs) {
        self.address = address;
    }

    /// Takes a n-byte message and the 32-byte seed for the private key to compute and return a signature.
    pub fn sign(&self, pub_seed: &Seed, msg: &[u8; N]) -> Signature {
        let mut sig = Signature {
            inner: [0; N * LEN],
            pub_seed: *pub_seed,
            address: self.address,
        };
        let lengths = concatenation(msg);
        let mut address = self.address;
        let mut ctr = [0u8; 32];

        for (i, n) in lengths.iter().enumerate() {
            ctr[31] = i as u8;
            address.set_chain(i as u32);
            chain(
                &mut sig.inner[(i * N)..(i * N + N)],
                &prf(&self.seed.0, &ctr), // i-th secret key
                0,
                *n as usize,
                pub_seed,
                address,
            );
        }

        sig
    }
}

/// WOTS+ public key
#[derive(Clone)]
pub struct PubKey {
    inner: [u8; N * LEN],
    pub_seed: Seed,
    address: Adrs,
}

impl PubKey {
    /// WOTS public key generation. Takes a 32 byte seed for the private key, expands it to
    /// a full WOTS private key and computes the corresponding public key.
    /// It requires the private key and a pub_seed (used to generate bitmasks and hash keys).
    pub fn from_seckey(seckey: &SecKey, pub_seed: &Seed) -> Self {
        let mut pubkey = Self {
            inner: [0; N * LEN],
            pub_seed: *pub_seed,
            address: seckey.address,
        };
        let mut address = seckey.address;
        let mut ctr = [0u8; 32];

        
        for i in 0..LEN {
            ctr[31] = i as u8;
            address.set_chain(i as u32);
            chain(
                &mut pubkey.inner[(i * N)..(i * N + N)],
                &prf(&seckey.seed.0, &ctr), // i-th secret key
                0,
                W - 1,
                pub_seed,
                address,
            );
        }

        pubkey
    }

    /// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
    pub fn from_signature(sig: &Signature, msg: &[u8; N]) -> Self {
        let lengths = concatenation(msg);
        let mut address = sig.address;
        let mut pubkey = Self {
            inner: [0; N * LEN],
            pub_seed: sig.pub_seed,
            address: sig.address,
        };

        for (i, n) in lengths.iter().enumerate() {
            address.set_chain(i as u32);
            chain(
                &mut pubkey.inner[(i * N)..(i * N + N)],
                &sig.inner[(i * N)..(i * N + N)],
                *n as usize,
                W - 1 - *n as usize,
                &sig.pub_seed,
                address,
            );
        }

        pubkey
    }
}

/// Computes the chaining function.
/// output and input have to be N-byte arrays.
/// Interprets input as start-th value of the chain.
/// address has to contain the address of the chain.
fn chain(
    output: &mut [u8],
    input: &[u8],
    start: usize,
    steps: usize,
    pub_seed: &Seed,
    address: Adrs,
) {
    output.copy_from_slice(input);
    let mut address = address;

    for i in start..(start + steps) {
        if i < W {
            address.set_hash(i as u32);
            address.set_keymask(0);
            let key = prf(&pub_seed.0, &address.0);
            address.set_keymask(1);
            let mut bitmask = prf(&pub_seed.0, &address.0);
            for i in 0..N {
                bitmask[i] = output[i] ^ bitmask[i];
            }
            output.copy_from_slice(&hash_f(&key, &bitmask));
        }
    }
}

/// Concatenation of the base-`W` representations of the message and its checksum.
fn concatenation(msg: &[u8; N]) -> [u8; LEN] {
    let mut output = [0u8; LEN];

    // Compute base-`W` representations of the message
    base_w(&mut output[0..L1], msg);

    // Computes checksum
    let mut csum = output[0..L1]
        .iter()
        .fold(0, |acc, &x| acc + W - 1 - x as usize);

    // Convert checksum to base_w.
    // Make sure expected empty zero bits are the least significant bits.
    csum = csum << (8 - ((L2 * LOG_W) % 8));
    let mut csum_bytes = [0u8; ((L2 * LOG_W) + 7) / 8];
    byte_array(&mut csum_bytes, csum);
    base_w(&mut output[L1..LEN], &csum_bytes);

    output
}

/// base_w algorithm as described in draft.
/// Interprets an array of bytes as integers in base w.
/// This only works when log_w is a divisor of 8.
fn base_w(output: &mut [u8], input: &[u8]) {
    let mut i = 0;
    let mut bits = 0;
    let mut total: u8 = 0;
    for out in output.iter_mut() {
        if bits == 0 {
            total = input[i];
            i += 1;
            bits += 8;
        }
        bits -= LOG_W;
        *out = (total >> bits) & (W - 1) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key() {
        let mut sk = SecKey::default();
        sk.set_seed(Seed::new());
        let pub_seed = Seed::default();
        let pk = PubKey::from_seckey(&sk, &pub_seed);
        let msg: [u8;N] = rand::random();
        let sig = sk.sign(&pub_seed, &msg);
        let pk2 = PubKey::from_signature(&sig, &msg);
        
        
        for i in 0..N*LEN {
            assert_eq!(pk.inner[i], pk2.inner[i]);
        }
    }
}
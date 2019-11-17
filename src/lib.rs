//#![allow(dead_code)]
#![no_std]

use rand;

mod hash;
use hash::{hash_f, prf};

/// The message length as well as the length of a private key, public key, or signature element in bytes.
const N: usize = 32;
/// The Winternitz parameter; it is a member of the set {4, 16}.
const W: usize = 16;
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
    pub fn new() -> Self {
        Self(rand::random())
    }
}

/// The address to randomize each hash function call to prevent multi-target attacks on the used hash function.
#[derive(Clone, Copy, Default, Debug)]
pub struct Adrs([u8; 32]);

impl Adrs {
    pub fn new() -> Self {
        Self(rand::random())
    }

    /// Set the chain field of a WOTS+ address to the given value.
    pub fn set_chain(&mut self, c: u32) {
        unsafe {
            self.0.as_mut_ptr().offset(20).copy_from(c as *mut u8, 4);
        }
    }

    /// Set the hash field of a WOTS+ address to the given value.
    pub fn set_hash(&mut self, h: u32) {
        unsafe {
            self.0.as_mut_ptr().offset(24).copy_from(h as *mut u8, 4);
        }
    }

    /// Set the keymask field of a WOTS+ address to the given value.
    pub fn set_keymask(&mut self, b: u32) {
        unsafe {
            self.0.as_mut_ptr().offset(28).copy_from(b as *mut u8, 4);
        }
    }
}

/// WOTS+ private key that hasn't expanded yet. It contain a seed to derive and an address for the key pair
#[derive(Clone, Default)]
pub struct SecKey {
    seed: Seed,
    address: Adrs,
}

impl SecKey {
    pub fn new() -> Self {
        Self {
            seed: Seed::new(),
            address: Adrs::new(),
        }
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
    pub fn from_sec_key(sec_key: &SecKey, pub_seed: &Seed) -> Self {
        let mut pub_key = Self {
            inner: [0; N * LEN],
            pub_seed: *pub_seed,
            address: sec_key.address,
        };

        let mut address = sec_key.address;
        for i in 0..LEN {
            address.set_chain(i as u32);
            let sec_key = prf(&sec_key.seed.0, &address.0);
            chain(
                &mut pub_key.inner[(i * N)..(i * N + N)],
                &sec_key,
                0,
                W - 1,
                pub_seed,
                &mut address,
            );
        }

        pub_key
    }
}

/// Computes the chaining function.
/// output and input have to be N-byte arrays.
/// Interprets input as start-th value of the chain.
/// address has to contain the address of the chain.
fn chain(
    output: &mut [u8],
    input: &[u8; N],
    start: usize,
    steps: usize,
    pub_seed: &Seed,
    address: &mut Adrs,
) {
    for i in start..(start + steps) {
        if i < W {
            address.set_hash(0);
            address.set_keymask(0);
            let key = prf(&pub_seed.0, &address.0);
            address.set_keymask(1);
            let mut bitmask = prf(&pub_seed.0, &address.0);
            for i in 0..N {
                bitmask[i] = input[i] ^ bitmask[i];
            }
            output.copy_from_slice(&hash_f(&key, &bitmask));
        }
    }
}

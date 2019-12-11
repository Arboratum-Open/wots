//! To fully describe a WOTS+ signature method, the parameters n and w,
//! as well as the functions F and PRF, MUST be specified.  The following
//! table defines several WOTS+ signature systems, each of which is
//! identified by a name.  Naming follows this convention:
//! WOTSP-[Hashfamily]_[n in bits].  Naming does not include w as all
//! parameter sets in this document use w=16.  Values for len are
//! provided for convenience.
//! 
//! +-----------------+----------+----+----+-----+
//! | Name            | F / PRF  |  n |  w | len |
//! +-----------------+----------+----+----+-----+
//! | REQUIRED:       |          |    |    |     |
//! |                 |          |    |    |     |
//! | WOTSP-SHA2_256  | SHA2-256 | 32 | 16 |  67 |
//! |                 |          |    |    |     |
//! | OPTIONAL:       |          |    |    |     |
//! |                 |          |    |    |     |
//! | WOTSP-SHA2_512  | SHA2-512 | 64 | 16 | 131 |
//! |                 |          |    |    |     |
//! | WOTSP-SHAKE_256 | SHAKE128 | 32 | 16 |  67 |
//! |                 |          |    |    |     |
//! | WOTSP-SHAKE_512 | SHAKE256 | 64 | 16 | 131 |
//! +-----------------+----------+----+----+-----+

/// The message length as well as the length of a private key, public key, or signature element in bytes.
#[cfg(any(feature = "WOTSP-SHA2_256", feature = "WOTSP-SHAKE_256"))]
pub(crate) const N: usize = 32;
#[cfg(any(feature = "WOTSP-SHA2_512", feature = "WOTSP-SHAKE_512"))]
pub(crate) const N: usize = 64;

/// The Winternitz parameter; it is a member of the set {4, 16}.
pub(crate) const W: usize = 16;

/// Log of Winternitz parameter
pub(crate) const LOG_W: usize = 4;

/// L1 = ceil(8N / lg(W))
#[cfg(any(feature = "WOTSP-SHA2_256", feature = "WOTSP-SHAKE_256"))]
pub(crate) const L1: usize = 64;
#[cfg(any(feature = "WOTSP-SHA2_512", feature = "WOTSP-SHAKE_512"))]
pub(crate) const L1: usize = 128;

/// L2 = floor(lg(L1 * (W - 1)) / lg(W)) + 1
pub(crate) const L2: usize = 3;

/// The number of N-byte string elements in a WOTS+ private key, public key, and signature.
pub(crate) const LEN: usize = L1 + L2;
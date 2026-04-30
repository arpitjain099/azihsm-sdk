// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elliptic Curve Cryptography (ECC) trait for the HSM PAL.
//!
//! Defines [`EccCurve`] and the [`HsmEcc`] trait that PAL implementations
//! use to expose ECC key generation, raw EC sign/verify, and ECDSA
//! sign/verify operations.
//!
//! **Status**: The trait is defined but not yet included in the
//! [`HsmCrypto`] supertrait bound — no PAL implements it yet. It will
//! be wired in when the `EccSign`, `EccGenerateKeyPair`, and
//! `EcdhKeyExchange` DDI handlers are implemented in `fw/core`.
//!
//! ## Output buffer convention
//!
//! All methods that produce output take mandatory `&mut` parameters.
//! The caller is responsible for providing buffers of the correct size.
//! Use [`EccCurve::priv_key_len`], [`EccCurve::pub_key_len`],
//! [`EccCurve::sig_len`], and [`EccCurve::secret_len`] to determine
//! the required sizes.
//!
//! ## Raw EC vs ECDSA
//!
//! - **`ecc_sign` / `ecc_verify`** — Raw EC operations on a pre-computed
//!   hash digest. The caller is responsible for hashing the message first.
//! - **`ecdsa_sign` / `ecdsa_verify`** — Full ECDSA with algorithm
//!   selection. The implementation hashes internally using `hash_algo`.

use super::*;

/// Supported NIST elliptic curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmEccCurve {
    /// NIST P-256 (secp256r1) — 32-byte key components.
    P256,

    /// NIST P-384 (secp384r1) — 48-byte key components.
    P384,

    /// NIST P-521 (secp521r1) — 66-byte key components.
    P521,
}

impl HsmEccCurve {
    /// Return the size in bytes of the private key for this curve.
    pub fn priv_key_len(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }

    /// Return the public key size in bytes (X + Y coordinates).
    ///
    /// Public keys are represented as the concatenation of the X and Y
    /// coordinates, each padded to 4-byte alignment to match PKA
    /// hardware output.  For P-256 (32) and P-384 (48) the coordinate
    /// sizes are already aligned; P-521 pads from 66 → 68 bytes per
    /// coordinate.
    pub fn pub_key_len(&self) -> usize {
        self.pka_coord_len() * 2
    }

    /// Return the raw (unpadded) coordinate size in bytes.
    fn raw_coord_len(&self) -> usize {
        self.priv_key_len()
    }

    /// Return the PKA-native coordinate size (4-byte aligned).
    fn pka_coord_len(&self) -> usize {
        self.raw_coord_len().next_multiple_of(4)
    }

    /// Return the ECDSA signature size in bytes (R + S values).
    ///
    /// ECDSA signatures are represented as the concatenation of the R and S
    /// values, each of which is `priv_key_len()` bytes.
    pub fn sig_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the ECDH shared secret size in bytes.
    ///
    /// The shared secret derived from ECDH is the same length as the private
    /// key for the selected curve.
    pub fn secret_len(&self) -> usize {
        self.priv_key_len()
    }

    /// Maximum PKCS#8 DER size for a private key on this curve.
    ///
    /// Callers use this to allocate buffers for
    /// [`ecc_gen_keypair`](HsmEcc::ecc_gen_keypair).
    ///
    /// TODO: Remove this
    pub fn priv_key_der_max(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 138,
            HsmEccCurve::P384 => 185,
            HsmEccCurve::P521 => 241,
        }
    }
}

/// ECC Pairwise Consistency Test (PCT) type used to indicate which
/// operation should be exercised in a self-test: none, signing, or key
/// agreement.
pub enum HsmEccPct {
    None,
    SignVerify,
    KeyAgreement,
}

/// Asynchronous ECC operations trait.
///
/// PAL implementations provide this to the core for ECC key generation,
/// signing, and verification. The async signatures allow hardware-backed
/// implementations to yield while the PKA engine processes operations.
///
/// All key parameters are plain `&[u8]` byte slices containing
/// DER-encoded key material (PKCS#8 for private keys, SPKI for public
/// keys). Each PAL implementation is responsible for parsing them into
/// whatever internal representation it needs.
pub trait HsmEcc {
    /// Generate an ECC key pair on the specified curve.
    ///
    /// Writes PKCS#8 DER private key into `priv_key` (pass `None` to
    /// query size).  Writes raw public key coordinates (x ∥ y) into
    /// `pub_key` — fixed size per curve: [`HsmEccCurve::pub_key_len`].
    ///
    /// # Wire format
    ///
    /// `pub_key` receives PKA-native byte order: **little-endian X
    /// concatenated with little-endian Y**, matching the output of real
    /// PKA hardware (Cortex-M7 and compatible). Consumers that need
    /// big-endian (e.g. X.509 SubjectPublicKeyInfo, the host SDK when
    /// the device advertises `Virtual`) must reverse each half.
    ///
    /// # Returns
    /// The actual private key DER length written.
    ///
    /// # Parameters
    /// - `curve` — The NIST curve to use for key generation.
    /// - `priv_key` — `None` to query size, `Some(buf)` for PKCS#8 DER output.
    /// - `pub_key` — Output buffer for raw coordinates (x ∥ y) in
    ///   PKA-native (little-endian) byte order.  Must be at least
    ///   [`HsmEccCurve::pub_key_len`] bytes.
    /// - `pct` — Pairwise Consistency Test mode.
    async fn ecc_gen_keypair(
        &self,
        curve: HsmEccCurve,
        priv_key: Option<&mut [u8]>,
        pub_key: &mut [u8],
        pct: HsmEccPct,
    ) -> HsmResult<usize>;

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// # Wire format
    ///
    /// `priv_key` and `signature` use the byte representations
    /// produced by [`ecc_gen_keypair`](Self::ecc_gen_keypair) and
    /// related host-side codecs:
    ///
    /// * `priv_key` — PKCS#8-DER encoded private key. The curve is
    ///   extracted from the DER metadata.
    /// * `signature` — Raw `r ‖ s` (no DER framing). Length must be
    ///   `2 * curve.point_size()`.
    ///
    /// # Errors
    /// Returns [`HsmError`] if signing fails or the buffer is too small.
    async fn ecc_sign(&self, priv_key: &[u8], hash: &[u8], signature: &mut [u8]) -> HsmResult<()>;

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// # Wire format
    ///
    /// * `pub_key` — Raw public key in PKA-native byte order:
    ///   little-endian X concatenated with little-endian Y. The curve
    ///   is inferred from the buffer length:
    ///   `64` → P-256, `96` → P-384, `132` → P-521. Any other length
    ///   yields [`HsmError::InvalidArg`].
    /// * `signature` — Raw `r ‖ s` (no DER framing).
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the verify operation itself fails
    /// (distinct from a returned `false`, which means the signature
    /// is well-formed but does not match).
    async fn ecc_verify(&self, pub_key: &[u8], hash: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// Perform ECDH key agreement to derive a shared secret.
    ///
    /// # Wire format
    ///
    /// * `priv_key` — PKCS#8-DER private key (curve embedded).
    /// * `pub_key` — Raw public key as `LE X ‖ LE Y`; curve inferred
    ///   from length and validated against the private key's curve.
    /// * `secret` — Output buffer; written length is
    ///   `curve.point_size()`.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key agreement operation fails
    /// (e.g., PKA engine error, invalid public key point, mismatched
    /// curves on the two keys).
    async fn ecdh_derive(
        &self,
        priv_key: &[u8],
        pub_key: &[u8],
        secret: &mut [u8],
    ) -> HsmResult<()>;
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmEcc`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (DER byte slices)
//! and the [`StdEcc`](crate::drivers::ecc::StdEcc) driver (OpenSSL
//! key handles). The PAL impl is responsible for:
//!
//! 1. **Enum mapping** — [`HsmEccCurve`] → [`azihsm_crypto::EccCurve`].
//! 2. **Key serialization** — exporting generated handles to DER bytes
//!    (PKCS#8 for private, SPKI for public) in [`ecc_gen_keypair`].
//! 3. **Key deserialization** — importing DER bytes into handles for
//!    [`ecc_sign`], [`ecc_verify`], and [`ecdh_derive`].
//!
//! ## Key formats
//!
//! | Direction | Private key | Public key |
//! |-----------|-------------|------------|
//! | Trait → PAL (input) | PKCS#8 DER `&[u8]` | SPKI DER `&[u8]` |
//! | PAL → Trait (output) | PKCS#8 DER `&mut [u8]` | SPKI DER `&mut [u8]` |
//! | PAL → Driver (internal) | `EccPrivateKey` handle | `EccPublicKey` handle |
//!
//! ## Data flow (sign example)
//!
//! ```text
//! Core calls pal.ecc_sign(curve, priv_key_der, hash, sig_buf)
//!   → EccPrivateKey::from_bytes(priv_key_der)  // DER → handle
//!   → self.ecc.ecc_sign(&handle, hash)         // driver
//!     → WorkerPool → OpenSSL ECDSA
//!   → sig_buf[..len].copy_from_slice(&sig)     // result → caller
//! ```

use azihsm_crypto::EccCurve;

use super::*;

/// Map the PAL-level [`HsmEccCurve`] to the crypto library's
/// [`azihsm_crypto::EccCurve`].
fn to_ecc_curve(curve: HsmEccCurve) -> EccCurve {
    match curve {
        HsmEccCurve::P256 => EccCurve::P256,
        HsmEccCurve::P384 => EccCurve::P384,
        HsmEccCurve::P521 => EccCurve::P521,
    }
}

impl HsmEcc for StdHsmPal {
    /// Generate an ECC key pair on the specified curve.
    ///
    /// Delegates to [`StdEcc::gen_keypair`] which returns OpenSSL handles,
    /// then exports the private key as PKCS#8 DER and the public key as
    /// SPKI DER into the caller-provided buffers.
    ///
    /// # Parameters
    /// - `curve` — NIST curve (P-256, P-384, or P-521).
    /// - `priv_key` — Output buffer for PKCS#8 DER private key
    ///   (`None` to query required size).
    /// - `pub_key` — Output buffer for raw public-key coordinates in
    ///   PKA-native order: little-endian X ‖ little-endian Y. Must be
    ///   at least [`HsmEccCurve::pub_key_len`] bytes.
    /// - `_pct` — Pairwise consistency test mode (currently ignored).
    ///
    /// # Errors
    /// - [`HsmError::EccGenerateError`] — key generation failed.
    /// - [`HsmError::EccToDerError`] — DER export failed.
    /// - [`HsmError::EccInvalidKeyLength`] — output buffer too small.
    async fn ecc_gen_keypair(
        &self,
        curve: HsmEccCurve,
        priv_key: Option<&mut [u8]>,
        pub_key: &mut [u8],
        _pct: HsmEccPct,
    ) -> HsmResult<usize> {
        self.ecc
            .gen_keypair(to_ecc_curve(curve), priv_key, pub_key)
            .await
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Pass-through to [`StdEcc::ecc_sign`]. The PAL-trait byte-format
    /// contract is documented on the trait method itself.
    async fn ecc_sign(&self, priv_key: &[u8], hash: &[u8], signature: &mut [u8]) -> HsmResult<()> {
        self.ecc.ecc_sign(priv_key, hash, signature).await
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Pass-through to [`StdEcc::ecc_verify`]. The PAL-trait byte-format
    /// contract is documented on the trait method itself.
    async fn ecc_verify(&self, pub_key: &[u8], hash: &[u8], signature: &[u8]) -> HsmResult<bool> {
        self.ecc.ecc_verify(pub_key, hash, signature).await
    }

    /// ECDH key agreement — derives a shared secret.
    ///
    /// Pass-through to [`StdEcc::ecdh_derive`]. The PAL-trait byte-format
    /// contract is documented on the trait method itself.
    async fn ecdh_derive(
        &self,
        priv_key: &[u8],
        pub_key: &[u8],
        secret: &mut [u8],
    ) -> HsmResult<()> {
        self.ecc.ecdh_derive(priv_key, pub_key, secret).await
    }
}

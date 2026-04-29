// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std ECC driver — performs ECC operations via OpenSSL.
//!
//! Operates on [`azihsm_crypto`] key handle types directly
//! (`EccPrivateKey`, `EccPublicKey`). The public API accepts
//! references and slices; owned copies for the worker thread
//! boundary are made internally via `Clone` (cheap — OpenSSL
//! key handles are reference-counted).
//!
//! ## Supported operations
//!
//! | Method | Operation | Input | Output |
//! |--------|-----------|-------|--------|
//! | [`gen_keypair`] | Key generation | `EccCurve`, mut buffers | `priv_len: usize` |
//! | [`ecc_sign`] | Raw EC sign | `&EccPrivateKey`, `&[u8]` hash | `Vec<u8>` (r∥s) |
//! | [`ecc_verify`] | Raw EC verify | `&EccPublicKey`, `&[u8]` hash, `&[u8]` sig | `bool` |
//! | [`ecdh_derive`] | ECDH agreement | `&EccPrivateKey`, `&EccPublicKey` | writes `&mut [u8]` |
//!
//! ## Thread model
//!
//! All methods clone handles and input slices into owned buffers,
//! then dispatch to the tokio [`WorkerPool`]. The Embassy executor
//! yields while the worker runs, then copies results back.
//!
//! On real Cortex-M7 hardware, these operations would be offloaded
//! to a PKA (Public Key Accelerator) engine via DMA.

use azihsm_crypto::DeriveOp;
use azihsm_crypto::EccAlgo;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::EcdhAlgo;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::SignOp;
use azihsm_crypto::VerifyOp;
use azihsm_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Std ECC driver — software ECC via OpenSSL with async worker dispatch.
pub struct StdEcc {
    pool: WorkerPool,
}

impl StdEcc {
    /// Create a new ECC driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate an ECC key pair, writing PKA-native byte representations
    /// directly into caller-provided buffers.
    ///
    /// # Output formats
    ///
    /// * `priv_der` — When `Some`, receives the PKCS#8-DER private key.
    ///   When `None`, no write happens; the function still returns the
    ///   number of bytes that *would* be required.
    /// * `pub_le_raw` — Receives raw public-key coordinates as
    ///   little-endian X concatenated with little-endian Y. This matches
    ///   the byte order produced by real PKA hardware (Cortex-M7 and
    ///   compatible), and is also the format the host SDK expects when
    ///   the device advertises [`DdiDeviceKind::Physical`] (its
    ///   `pub_key_der_post_decode` hook reverses each half back to
    ///   big-endian before assembling DER). Buffer must be at least
    ///   `2 * curve.point_size()` bytes.
    ///
    /// # Returns
    ///
    /// The PKCS#8-DER private-key length (written to or required by
    /// `priv_der`).
    ///
    /// # Errors
    ///
    /// * [`HsmError::EccGenerateError`] / [`HsmError::EccGetCoordinatesError`]
    ///   — OpenSSL keygen / coordinate extraction failed.
    /// * [`HsmError::EccToDerError`] — DER export failed.
    /// * [`HsmError::EccInvalidKeyLength`] — caller-provided buffer too small.
    pub async fn gen_keypair(
        &self,
        curve: EccCurve,
        priv_der: Option<&mut [u8]>,
        pub_le_raw: &mut [u8],
    ) -> HsmResult<usize> {
        // Keygen on the worker thread (matches what real PKA hardware
        // would offload). Byte serialization happens on the caller
        // thread below so that we can write straight into the supplied
        // mutable slices.
        let (priv_key, pub_key) = self
            .pool
            .submit_with_result(async move {
                let priv_key =
                    EccPrivateKey::from_curve(curve).map_err(|_| HsmError::EccGenerateError)?;
                let pub_key = priv_key
                    .public_key()
                    .map_err(|_| HsmError::EccGetCoordinatesError)?;
                Ok::<_, HsmError>((priv_key, pub_key))
            })
            .await?;

        // ── Private key: PKCS#8 DER ───────────────────────────────
        let priv_len = priv_key
            .to_bytes(None)
            .map_err(|_| HsmError::EccToDerError)?;
        if let Some(buf) = priv_der {
            if buf.len() < priv_len {
                return Err(HsmError::EccInvalidKeyLength);
            }
            priv_key
                .to_bytes(Some(&mut buf[..priv_len]))
                .map_err(|_| HsmError::EccToDerError)?;
        }

        // ── Public key: PKA-native (little-endian) X ‖ Y ──────────
        let coord_len = curve.point_size() * 2;
        if pub_le_raw.len() < coord_len {
            return Err(HsmError::EccInvalidKeyLength);
        }
        let half = coord_len / 2;
        let (x_buf, y_buf) = pub_le_raw[..coord_len].split_at_mut(half);
        // OpenSSL emits big-endian; reverse each half in place to get
        // PKA-native little-endian.
        pub_key
            .coord(Some((x_buf, y_buf)))
            .map_err(|_| HsmError::EccGetCoordinatesError)?;
        x_buf.reverse();
        y_buf.reverse();

        Ok(priv_len)
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Clones the private key handle (cheap, ref-counted), copies the
    /// hash to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `priv_key` — The signing key handle.
    /// - `hash` — Pre-computed hash digest (e.g., SHA-256 output).
    ///
    /// # Returns
    /// The raw `r ∥ s` signature as a `Vec<u8>`. Length is
    /// `2 × curve.point_size()` (64 for P-256, 96 for P-384, 132 for P-521).
    ///
    /// # Errors
    /// Returns [`HsmError::EccSignFailed`] if the OpenSSL sign operation fails.
    pub async fn ecc_sign(&self, priv_key: &EccPrivateKey, hash: &[u8]) -> HsmResult<Vec<u8>> {
        let key = priv_key.clone();
        let hash_owned = hash.to_vec();
        self.pool
            .submit_with_result(async move {
                let sig_len = EccKeyOp::curve(&key).point_size() * 2;
                let mut sig = vec![0u8; sig_len];
                let mut algo = EccAlgo::default();
                algo.sign(&key, &hash_owned, Some(&mut sig))
                    .map_err(|_| HsmError::EccSignFailed)?;
                Ok(sig)
            })
            .await
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub async fn ecc_verify(
        &self,
        pub_key: &EccPublicKey,
        hash: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        let key = pub_key.clone();
        let hash_owned = hash.to_vec();
        let sig_owned = signature.to_vec();
        self.pool
            .submit_with_result(async move {
                let mut algo = EccAlgo::default();
                algo.verify(&key, &hash_owned, &sig_owned)
                    .map_err(|_| HsmError::EccVerifyFailed)
            })
            .await
    }

    /// ECDH key agreement — derives a shared secret into `secret`.
    ///
    /// Clones both key handles, dispatches ECDH computation to the worker
    /// pool, and copies the raw shared secret (x-coordinate of the
    /// shared point) into `secret`.
    ///
    /// # Parameters
    /// - `priv_key` — The local private key handle.
    /// - `pub_key` — The remote party's public key handle.
    /// - `secret` — Output buffer. Must be ≥ `curve.point_size()` bytes
    ///   (32 for P-256, 48 for P-384, 66 for P-521).
    ///
    /// # Errors
    /// - [`HsmError::EccDeriveError`] — ECDH computation, secret export,
    ///   or output buffer too small.
    pub async fn ecdh_derive(
        &self,
        priv_key: &EccPrivateKey,
        pub_key: &EccPublicKey,
        secret: &mut [u8],
    ) -> HsmResult<()> {
        let pk = priv_key.clone();
        let pubk = pub_key.clone();
        let result: HsmResult<Vec<u8>> = self
            .pool
            .submit_with_result(async move {
                let derived_len = EccKeyOp::curve(&pk).point_size();
                let ecdh = EcdhAlgo::new(&pubk);
                let derived = ecdh
                    .derive(&pk, derived_len)
                    .map_err(|_| HsmError::EccDeriveError)?;
                derived.to_vec().map_err(|_| HsmError::EccDeriveError)
            })
            .await;
        let bytes = result?;
        if secret.len() < bytes.len() {
            return Err(HsmError::EccDeriveError);
        }
        secret[..bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use azihsm_crypto::ImportableKey;
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdEcc {
        StdEcc::new(WorkerPool::new(Handle::current()))
    }

    /// Construct a fresh `(priv, pub)` handle pair without going through
    /// the byte-oriented driver API.  Used by sign/verify/ECDH tests
    /// which need handles for the next operation.
    fn make_handles(curve: EccCurve) -> (EccPrivateKey, EccPublicKey) {
        let priv_key = EccPrivateKey::from_curve(curve).unwrap();
        let pub_key = priv_key.public_key().unwrap();
        (priv_key, pub_key)
    }

    /// Reverse a (LE‖LE) raw public key into a (BE‖BE) form so it can be
    /// re-imported via [`EccPublicKey::from_coordinates`].
    fn le_raw_to_be_coords(le: &[u8], coord_size: usize) -> (Vec<u8>, Vec<u8>) {
        let half = coord_size;
        let mut be_x = vec![0u8; half];
        let mut be_y = vec![0u8; half];
        for i in 0..half {
            be_x[i] = le[half - 1 - i];
            be_y[i] = le[2 * half - 1 - i];
        }
        (be_x, be_y)
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_keypair_p256_byte_format() {
        let driver = make_driver();
        let mut priv_der = vec![0u8; 200];
        let mut pub_le = [0u8; 64];

        let priv_len = driver
            .gen_keypair(EccCurve::P256, Some(&mut priv_der), &mut pub_le)
            .await
            .unwrap();
        priv_der.truncate(priv_len);

        // Private key parses as PKCS#8 DER.
        let priv_key = EccPrivateKey::from_bytes(&priv_der).unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P256);

        // Reverse each half to BE, reconstruct the public key, and prove
        // it matches the private key by signing/verifying.
        let (be_x, be_y) = le_raw_to_be_coords(&pub_le, 32);
        let pub_key = EccPublicKey::from_coordinates(EccCurve::P256, &be_x, &be_y).unwrap();
        let hash = [0xABu8; 32];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn gen_keypair_p384_byte_format() {
        let driver = make_driver();
        let mut priv_der = vec![0u8; 256];
        let mut pub_le = [0u8; 96];

        let priv_len = driver
            .gen_keypair(EccCurve::P384, Some(&mut priv_der), &mut pub_le)
            .await
            .unwrap();
        priv_der.truncate(priv_len);

        let priv_key = EccPrivateKey::from_bytes(&priv_der).unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P384);

        let (be_x, be_y) = le_raw_to_be_coords(&pub_le, 48);
        let pub_key = EccPublicKey::from_coordinates(EccCurve::P384, &be_x, &be_y).unwrap();
        let hash = [0xCDu8; 48];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn gen_keypair_priv_size_query() {
        let driver = make_driver();
        let mut pub_le = [0u8; 96];
        let priv_len = driver
            .gen_keypair(EccCurve::P384, None, &mut pub_le)
            .await
            .unwrap();
        assert!(priv_len > 0);
    }

    #[tokio::test]
    async fn gen_keypair_pub_buffer_too_small() {
        let driver = make_driver();
        let mut pub_le = [0u8; 32]; // too small for P-384 (needs 96)
        let err = driver
            .gen_keypair(EccCurve::P384, None, &mut pub_le)
            .await
            .unwrap_err();
        assert_eq!(err, HsmError::EccInvalidKeyLength);
    }

    // ── Sign / verify roundtrip ─────────────────────────────────

    #[tokio::test]
    async fn sign_verify_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = make_handles(EccCurve::P256);
        let hash = [0xABu8; 32];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 64);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = make_handles(EccCurve::P384);
        let hash = [0xCDu8; 48];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 96);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = make_handles(EccCurve::P521);
        let hash = [0xEFu8; 64];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 132);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    // ── Verify with wrong hash ──────────────────────────────────

    #[tokio::test]
    async fn verify_wrong_hash_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = make_handles(EccCurve::P256);
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 32]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 32], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = make_handles(EccCurve::P384);
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 48]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 48], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = make_handles(EccCurve::P521);
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 64]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 64], &sig)
            .await
            .unwrap());
    }

    // ── ECDH shared secret ──────────────────────────────────────

    #[tokio::test]
    async fn ecdh_p256() {
        let driver = make_driver();
        let (priv_a, pub_a) = make_handles(EccCurve::P256);
        let (priv_b, pub_b) = make_handles(EccCurve::P256);
        let mut secret_ab = [0u8; 32];
        let mut secret_ba = [0u8; 32];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 32]);
    }

    #[tokio::test]
    async fn ecdh_p384() {
        let driver = make_driver();
        let (priv_a, pub_a) = make_handles(EccCurve::P384);
        let (priv_b, pub_b) = make_handles(EccCurve::P384);
        let mut secret_ab = [0u8; 48];
        let mut secret_ba = [0u8; 48];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 48]);
    }

    #[tokio::test]
    async fn ecdh_p521() {
        let driver = make_driver();
        let (priv_a, pub_a) = make_handles(EccCurve::P521);
        let (priv_b, pub_b) = make_handles(EccCurve::P521);
        let mut secret_ab = [0u8; 66];
        let mut secret_ba = [0u8; 66];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 66]);
    }
}

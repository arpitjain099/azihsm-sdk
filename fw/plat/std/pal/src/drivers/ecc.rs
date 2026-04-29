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
use azihsm_crypto::ImportableKey;
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
    /// Imports the private key from PKCS#8 DER (the format produced by
    /// [`gen_keypair`](Self::gen_keypair)), dispatches the signing
    /// operation to the worker pool, and writes the raw `r ∥ s`
    /// signature into the caller-supplied `sig` buffer.
    ///
    /// # Parameters
    /// - `curve` — The NIST curve hint. The actual curve is encoded in
    ///   the DER key; this parameter is used only to validate the
    ///   `sig` buffer size.
    /// - `priv_der` — PKCS#8 DER private key.
    /// - `hash` — Pre-computed hash digest (e.g., SHA-256 output).
    /// - `sig` — Output buffer. Must be ≥ `2 * curve.point_size()`
    ///   (64 / 96 / 132 bytes for P-256 / P-384 / P-521).
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — DER import failed or `sig` is too small.
    /// - [`HsmError::EccSignFailed`] — OpenSSL sign operation failed.
    pub async fn ecc_sign(&self, priv_der: &[u8], hash: &[u8], sig: &mut [u8]) -> HsmResult<()> {
        let priv_owned = priv_der.to_vec();
        let hash_owned = hash.to_vec();
        let bytes: Vec<u8> = self
            .pool
            .submit_with_result(async move {
                let priv_key =
                    EccPrivateKey::from_bytes(&priv_owned).map_err(|_| HsmError::InvalidArg)?;
                let curve = EccKeyOp::curve(&priv_key);
                let mut buf = vec![0u8; curve.point_size() * 2];
                let mut algo = EccAlgo::default();
                algo.sign(&priv_key, &hash_owned, Some(&mut buf))
                    .map_err(|_| HsmError::EccSignFailed)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;
        if sig.len() < bytes.len() {
            return Err(HsmError::InvalidArg);
        }
        sig[..bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Reconstructs the public key from PKA-native raw coordinates
    /// (the same `LE X ‖ LE Y` byte order produced by
    /// [`gen_keypair`](Self::gen_keypair)), dispatches the verify to
    /// the worker pool, and returns whether the signature is valid.
    ///
    /// # Parameters
    /// - `curve` — The NIST curve.
    /// - `pub_le_raw` — Public key as little-endian X ‖ little-endian
    ///   Y, exactly `2 * curve.point_size()` bytes.
    /// - `hash` — Pre-computed hash digest.
    /// - `sig` — Raw `r ∥ s` signature.
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — public key reconstruction failed.
    /// - [`HsmError::EccVerifyFailed`] — verify operation failed
    ///   (distinct from a returned `false`, which means valid-but-mismatched).
    pub async fn ecc_verify(&self, pub_le_raw: &[u8], hash: &[u8], sig: &[u8]) -> HsmResult<bool> {
        let curve = curve_from_raw_pub_len(pub_le_raw.len())?;
        let coord_len = curve.point_size();
        let (x_be, y_be) = le_raw_to_be_coords(pub_le_raw, coord_len);
        let hash_owned = hash.to_vec();
        let sig_owned = sig.to_vec();
        self.pool
            .submit_with_result(async move {
                let pub_key = EccPublicKey::from_coordinates(curve, &x_be, &y_be)
                    .map_err(|_| HsmError::InvalidArg)?;
                let mut algo = EccAlgo::default();
                algo.verify(&pub_key, &hash_owned, &sig_owned)
                    .map_err(|_| HsmError::EccVerifyFailed)
            })
            .await
    }

    /// ECDH key agreement — derives a shared secret into `secret`.
    ///
    /// Imports the local private key from PKCS#8 DER and the remote
    /// public key from PKA-native raw coordinates (the formats
    /// produced by [`gen_keypair`](Self::gen_keypair)), runs ECDH on
    /// the worker pool, and writes the raw shared secret into
    /// `secret`.
    ///
    /// # Parameters
    /// - `curve` — The NIST curve.
    /// - `priv_der` — Local PKCS#8 DER private key.
    /// - `pub_le_raw` — Remote public key as `LE X ‖ LE Y`,
    ///   `2 * curve.point_size()` bytes.
    /// - `secret` — Output buffer. Must be ≥ `curve.point_size()`
    ///   (32 / 48 / 66 bytes for P-256 / P-384 / P-521).
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — key import failed or `secret` too small.
    /// - [`HsmError::EccDeriveError`] — ECDH computation or export failed.
    pub async fn ecdh_derive(
        &self,
        priv_der: &[u8],
        pub_le_raw: &[u8],
        secret: &mut [u8],
    ) -> HsmResult<()> {
        let pub_curve = curve_from_raw_pub_len(pub_le_raw.len())?;
        let coord_len = pub_curve.point_size();
        if secret.len() < coord_len {
            return Err(HsmError::EccDeriveError);
        }
        let (x_be, y_be) = le_raw_to_be_coords(pub_le_raw, coord_len);
        let priv_owned = priv_der.to_vec();
        let bytes: Vec<u8> = self
            .pool
            .submit_with_result(async move {
                let priv_key =
                    EccPrivateKey::from_bytes(&priv_owned).map_err(|_| HsmError::InvalidArg)?;
                if EccKeyOp::curve(&priv_key) != pub_curve {
                    return Err(HsmError::InvalidArg);
                }
                let pub_key = EccPublicKey::from_coordinates(pub_curve, &x_be, &y_be)
                    .map_err(|_| HsmError::InvalidArg)?;
                let derived_len = pub_curve.point_size();
                let ecdh = EcdhAlgo::new(&pub_key);
                let derived = ecdh
                    .derive(&priv_key, derived_len)
                    .map_err(|_| HsmError::EccDeriveError)?;
                derived.to_vec().map_err(|_| HsmError::EccDeriveError)
            })
            .await?;
        secret[..bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }
}

/// Infer the NIST curve from the length of a raw `LE X ‖ LE Y` public
/// key encoding.
///
/// | Length | Curve  |
/// |-------:|--------|
/// |     64 | P-256  |
/// |     96 | P-384  |
/// |    132 | P-521  |
///
/// Any other length yields [`HsmError::InvalidArg`].
fn curve_from_raw_pub_len(len: usize) -> HsmResult<EccCurve> {
    match len {
        64 => Ok(EccCurve::P256),
        96 => Ok(EccCurve::P384),
        132 => Ok(EccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Reverse each coordinate half (LE → BE) so OpenSSL's
/// big-endian-expecting APIs accept the result. Stateless helper used
/// by `ecc_verify` and `ecdh_derive`.
fn le_raw_to_be_coords(le: &[u8], coord_size: usize) -> (Vec<u8>, Vec<u8>) {
    let mut be_x = vec![0u8; coord_size];
    let mut be_y = vec![0u8; coord_size];
    for i in 0..coord_size {
        be_x[i] = le[coord_size - 1 - i];
        be_y[i] = le[2 * coord_size - 1 - i];
    }
    (be_x, be_y)
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdEcc {
        StdEcc::new(WorkerPool::new(Handle::current()))
    }

    /// Generate a fresh keypair via the public byte-oriented API and
    /// return `(priv_der, pub_le_raw)` ready to feed into `ecc_sign`,
    /// `ecc_verify`, and `ecdh_derive`.
    async fn make_byte_keys(driver: &StdEcc, curve: EccCurve) -> (Vec<u8>, Vec<u8>) {
        let mut priv_der = vec![0u8; 256];
        let mut pub_le = vec![0u8; curve.point_size() * 2];
        let priv_len = driver
            .gen_keypair(curve, Some(&mut priv_der), &mut pub_le)
            .await
            .unwrap();
        priv_der.truncate(priv_len);
        (priv_der, pub_le)
    }

    // ── Key generation ──────────────────────────────────────────

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
    //
    // These also implicitly verify the byte-format contract: the
    // public key is consumed via `ecc_verify(curve, pub_le_raw, …)`,
    // so a successful verify proves `gen_keypair` emitted PKA-native
    // (LE) bytes that match what the driver expects.

    #[tokio::test]
    async fn sign_verify_p256() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P256).await;
        let hash = [0xABu8; 32];
        let mut sig = vec![0u8; 64];
        driver.ecc_sign(&priv_der, &hash, &mut sig).await.unwrap();
        assert!(driver.ecc_verify(&pub_le, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p384() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P384).await;
        let hash = [0xCDu8; 48];
        let mut sig = vec![0u8; 96];
        driver.ecc_sign(&priv_der, &hash, &mut sig).await.unwrap();
        assert!(driver.ecc_verify(&pub_le, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p521() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P521).await;
        let hash = [0xEFu8; 64];
        let mut sig = vec![0u8; 132];
        driver.ecc_sign(&priv_der, &hash, &mut sig).await.unwrap();
        assert!(driver.ecc_verify(&pub_le, &hash, &sig).await.unwrap());
    }

    // ── Verify with wrong hash ──────────────────────────────────

    #[tokio::test]
    async fn verify_wrong_hash_p256() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P256).await;
        let mut sig = vec![0u8; 64];
        driver
            .ecc_sign(&priv_der, &[0xAAu8; 32], &mut sig)
            .await
            .unwrap();
        assert!(!driver
            .ecc_verify(&pub_le, &[0xBBu8; 32], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p384() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P384).await;
        let mut sig = vec![0u8; 96];
        driver
            .ecc_sign(&priv_der, &[0xAAu8; 48], &mut sig)
            .await
            .unwrap();
        assert!(!driver
            .ecc_verify(&pub_le, &[0xBBu8; 48], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p521() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P521).await;
        let mut sig = vec![0u8; 132];
        driver
            .ecc_sign(&priv_der, &[0xAAu8; 64], &mut sig)
            .await
            .unwrap();
        assert!(!driver
            .ecc_verify(&pub_le, &[0xBBu8; 64], &sig)
            .await
            .unwrap());
    }

    // ── ECDH shared secret ──────────────────────────────────────

    #[tokio::test]
    async fn ecdh_p256() {
        let driver = make_driver();
        let (priv_a, pub_a) = make_byte_keys(&driver, EccCurve::P256).await;
        let (priv_b, pub_b) = make_byte_keys(&driver, EccCurve::P256).await;
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
        let (priv_a, pub_a) = make_byte_keys(&driver, EccCurve::P384).await;
        let (priv_b, pub_b) = make_byte_keys(&driver, EccCurve::P384).await;
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
        let (priv_a, pub_a) = make_byte_keys(&driver, EccCurve::P521).await;
        let (priv_b, pub_b) = make_byte_keys(&driver, EccCurve::P521).await;
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

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
        // OpenSSL emits big-endian coordinates at the raw size (66B for
        // P-521). We reverse each to get LE, then zero-pad to the
        // PKA-native 4-byte-aligned coordinate size (68B for P-521).
        let raw_half = curve.point_size();
        let pka_half = raw_half.next_multiple_of(4);
        let pka_total = pka_half * 2;
        if pub_le_raw.len() < pka_total {
            return Err(HsmError::EccInvalidKeyLength);
        }
        // Zero the full PKA output region first (handles padding).
        pub_le_raw[..pka_total].fill(0);
        {
            // Extract raw BE coords into temporary buffers.
            let mut x_be = [0u8; 68];
            let mut y_be = [0u8; 68];
            pub_key
                .coord(Some((&mut x_be[..raw_half], &mut y_be[..raw_half])))
                .map_err(|_| HsmError::EccGetCoordinatesError)?;
            // Reverse to LE and write into the PKA-native slots.
            for i in 0..raw_half {
                pub_le_raw[i] = x_be[raw_half - 1 - i];
                pub_le_raw[pka_half + i] = y_be[raw_half - 1 - i];
            }
            // Trailing pad bytes (pka_half - raw_half) are already zero.
        }

        Ok(priv_len)
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Matches real PKA hardware: accepts a **little-endian** digest
    /// (the caller reverses SHA's BE output before calling) and
    /// produces a **PKA-native LE** signature (`LE r ‖ LE s`), each
    /// component padded to 4-byte alignment (68 bytes for P-521).
    pub async fn ecc_sign(&self, priv_der: &[u8], hash_le: &[u8], sig: &mut [u8]) -> HsmResult<()> {
        let priv_owned = priv_der.to_vec();
        let hash_le_owned = hash_le.to_vec();
        let bytes: Vec<u8> = self
            .pool
            .submit_with_result(async move {
                let priv_key =
                    EccPrivateKey::from_bytes(&priv_owned).map_err(|_| HsmError::InvalidArg)?;
                let curve = EccKeyOp::curve(&priv_key);
                let raw_half = curve.point_size();
                let pka_half = raw_half.next_multiple_of(4);

                // Convert LE digest → BE for OpenSSL, trimming pad zeros.
                let mut hash_be = hash_le_owned;
                hash_be.reverse();
                let trim = hash_be
                    .iter()
                    .position(|&b| b != 0)
                    .unwrap_or(hash_be.len());
                let digest_be = if trim >= hash_be.len() {
                    &[0u8] as &[u8]
                } else {
                    &hash_be[trim..]
                };

                let mut buf = vec![0u8; raw_half * 2];
                let mut algo = EccAlgo::default();
                algo.sign(&priv_key, digest_be, Some(&mut buf))
                    .map_err(|_| HsmError::EccSignFailed)?;

                // OpenSSL emits BE r ‖ BE s. Build PKA-native LE output:
                // reverse each component and place into pka-sized slots.
                let mut pka_buf = vec![0u8; pka_half * 2];
                for i in 0..raw_half {
                    pka_buf[i] = buf[raw_half - 1 - i];
                    pka_buf[pka_half + i] = buf[raw_half + raw_half - 1 - i];
                }
                Ok::<_, HsmError>(pka_buf)
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
    /// Matches real PKA hardware: accepts **little-endian** hash,
    /// PKA-native LE signature, and PKA-native LE public key.
    pub async fn ecc_verify(
        &self,
        pub_le_raw: &[u8],
        hash_le: &[u8],
        sig_le: &[u8],
    ) -> HsmResult<bool> {
        let curve = curve_from_raw_pub_len(pub_le_raw.len())?;
        let raw_coord = curve.point_size();
        let pka_coord = raw_coord.next_multiple_of(4);
        if sig_le.len() != pka_coord * 2 {
            return Err(HsmError::InvalidArg);
        }
        let (x_be, y_be) = le_raw_to_be_coords(pub_le_raw, raw_coord);
        // Convert LE digest → BE for OpenSSL.
        let mut hash_be = hash_le.to_vec();
        hash_be.reverse();
        let trim = hash_be
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(hash_be.len());
        let hash_trimmed = if trim >= hash_be.len() {
            vec![0u8]
        } else {
            hash_be[trim..].to_vec()
        };
        // Convert PKA-native LE sig → raw BE sig for OpenSSL.
        let mut sig_be = vec![0u8; raw_coord * 2];
        for i in 0..raw_coord {
            sig_be[i] = sig_le[raw_coord - 1 - i];
            sig_be[raw_coord + i] = sig_le[pka_coord + raw_coord - 1 - i];
        }
        self.pool
            .submit_with_result(async move {
                let pub_key = EccPublicKey::from_coordinates(curve, &x_be, &y_be)
                    .map_err(|_| HsmError::InvalidArg)?;
                let mut algo = EccAlgo::default();
                algo.verify(&pub_key, &hash_trimmed, &sig_be)
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
        136 => Ok(EccCurve::P521), // PKA-native: 68 * 2
        _ => Err(HsmError::InvalidArg),
    }
}

/// Reverse each coordinate half (LE → BE) so OpenSSL's
/// big-endian-expecting APIs accept the result. Stateless helper used
/// by `ecc_verify` and `ecdh_derive`.
/// Convert PKA-native LE coordinates to BE for OpenSSL.
///
/// `le` is `[LE_X (pka_coord) ‖ LE_Y (pka_coord)]` where `pka_coord`
/// is `raw_coord_size` rounded up to 4-byte alignment (same for
/// P-256/P-384; 66→68 for P-521). Only the first `raw_size` bytes of
/// each half carry data; trailing pad bytes are ignored.
fn le_raw_to_be_coords(le: &[u8], raw_size: usize) -> (Vec<u8>, Vec<u8>) {
    let pka_size = raw_size.next_multiple_of(4);
    let mut be_x = vec![0u8; raw_size];
    let mut be_y = vec![0u8; raw_size];
    for i in 0..raw_size {
        be_x[i] = le[raw_size - 1 - i];
        be_y[i] = le[pka_size + raw_size - 1 - i];
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
        let pka_coord = curve.point_size().next_multiple_of(4);
        let mut pub_le = vec![0u8; pka_coord * 2];
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
        let mut hash_le = [0xABu8; 32];
        hash_le.reverse();
        let mut sig = vec![0u8; 64];
        driver
            .ecc_sign(&priv_der, &hash_le, &mut sig)
            .await
            .unwrap();
        assert!(driver.ecc_verify(&pub_le, &hash_le, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p384() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P384).await;
        let mut hash_le = [0xCDu8; 48];
        hash_le.reverse();
        let mut sig = vec![0u8; 96];
        driver
            .ecc_sign(&priv_der, &hash_le, &mut sig)
            .await
            .unwrap();
        assert!(driver.ecc_verify(&pub_le, &hash_le, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p521() {
        let driver = make_driver();
        let (priv_der, pub_le) = make_byte_keys(&driver, EccCurve::P521).await;
        let mut hash_le = [0xEFu8; 64];
        hash_le.reverse();
        let mut sig = vec![0u8; 136];
        driver
            .ecc_sign(&priv_der, &hash_le, &mut sig)
            .await
            .unwrap();
        assert!(driver.ecc_verify(&pub_le, &hash_le, &sig).await.unwrap());
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
        let mut sig = vec![0u8; 136];
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

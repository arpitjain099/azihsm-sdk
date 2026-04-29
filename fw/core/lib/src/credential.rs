// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Credential decryption helpers used by `EstablishCredential` and
//! (in iter 6) `OpenSession`.
//!
//! Both DDI commands receive the user's `(id, pin)` pair encrypted by
//! the host with a key derived via ECDH between an ephemeral host key
//! and a partition-resident ECC key. The unwrap algorithm is identical
//! across the two ops; only the surrounding context differs.
//!
//! # Algorithm (ECDH-then-HKDF-SHA384, AES-CBC-256 + HMAC-SHA-384)
//!
//! 1. `shared = ECDH(partition_priv_der, host_pub_le_raw)`            (48B)
//! 2. `keys   = HKDF-SHA384(ikm = shared, salt = none, info = nonce, L = 80B)`
//!    `aes_key  = keys[..32]`
//!    `hmac_key = keys[32..]`
//! 3. Verify `HMAC-SHA384(hmac_key, encrypted_id || encrypted_pin || iv || nonce)
//!    == received_tag`              (constant-time inside the PAL)
//! 4. Decrypt `id  = AES-CBC-256(aes_key, iv,  encrypted_id)`         (16B)
//! 5. Decrypt `pin = AES-CBC-256(aes_key, iv', encrypted_pin)`        (16B)
//!    where `iv'` is the last ciphertext block from step 4 (the
//!    encrypted_id ciphertext itself, which `aes_cbc_enc_dec` updates
//!    `iv` to in-place).
//!
//! Mirrors `ddi/sim/src/vault.rs::establish_credential` lines 711-756
//! and the equivalent `mcr-hsm/.../partition/cred_mgr.rs` flow.

use azihsm_fw_hsm_pal_traits::*;

/// Length of the user ID and PIN payloads (one AES block each).
pub const ID_LEN: usize = 16;
pub const PIN_LEN: usize = 16;
/// AES-CBC IV length.
pub const IV_LEN: usize = 16;
/// Partition nonce length.
pub const NONCE_LEN: usize = 32;
/// HMAC-SHA-384 tag length.
pub const TAG_LEN: usize = 48;
/// Combined AES-256 key + HMAC-SHA-384 key length.
const KEYS_LEN: usize = 32 + 48;

/// Decrypt the `(id, pin)` pair carried by an EstablishCredential or
/// OpenSession request.
///
/// # Parameters
/// * `pal` — PAL providing ECDH, HKDF, AES, HMAC.
/// * `partition_priv_der` — PKCS#8 DER private key for the partition's
///   establish-cred (or session-cred) ECC P-384 key.
/// * `host_pub_le_raw` — Host's ephemeral ECC public key in PKA-native
///   `LE X || LE Y` (96 bytes for P-384).
/// * `partition_nonce` — The partition's current 32-byte nonce; the
///   host included this in the ciphertext at IV time.
/// * `encrypted_id` — 16-byte ciphertext of the user ID.
/// * `encrypted_pin` — 16-byte ciphertext of the PIN.
/// * `iv` — 16-byte AES-CBC IV used by the host.
/// * `tag` — 48-byte HMAC-SHA-384 tag covering
///   `encrypted_id || encrypted_pin || iv || partition_nonce`.
///
/// # Returns
/// `(id, pin)` — both 16 bytes, recovered plaintext.
///
/// # Errors
/// * [`HsmError::PinDecryptionFailed`] — HMAC tag mismatch.
/// * [`HsmError::EccDeriveError`], [`HsmError::AesDecryptFailed`] — propagated
///   from the underlying PAL operations.
pub async fn unwrap_credential<P: HsmPal>(
    pal: &P,
    partition_priv_der: &[u8],
    host_pub_le_raw: &[u8],
    partition_nonce: &[u8; NONCE_LEN],
    encrypted_id: &[u8],
    encrypted_pin: &[u8],
    iv: &[u8],
    tag: &[u8],
) -> HsmResult<([u8; ID_LEN], [u8; PIN_LEN])> {
    if encrypted_id.len() != ID_LEN
        || encrypted_pin.len() != PIN_LEN
        || iv.len() != IV_LEN
        || tag.len() != TAG_LEN
    {
        return Err(HsmError::InvalidArg);
    }

    // 1. ECDH → shared secret (48 bytes for P-384).
    let mut shared = [0u8; 48];
    pal.ecdh_derive(partition_priv_der, host_pub_le_raw, &mut shared)
        .await?;

    // 2. HKDF-SHA384(shared, salt=&[], info=nonce, len=80) → AES key + HMAC key.
    let mut keys = [0u8; KEYS_LEN];
    pal.hkdf(
        &shared,
        HsmHashAlgo::Sha384,
        HkdfMode::ExtractAndExpand,
        &[],
        partition_nonce,
        &mut keys,
    )
    .await?;
    // SAFETY: KEYS_LEN = 80, splits cleanly at 32.
    let (aes_key, hmac_key) = keys.split_at(32);

    // 3. HMAC verify over (encrypted_id || encrypted_pin || iv || nonce).
    let mut hmac_input = [0u8; ID_LEN + PIN_LEN + IV_LEN + NONCE_LEN];
    hmac_input[..ID_LEN].copy_from_slice(encrypted_id);
    hmac_input[ID_LEN..ID_LEN + PIN_LEN].copy_from_slice(encrypted_pin);
    hmac_input[ID_LEN + PIN_LEN..ID_LEN + PIN_LEN + IV_LEN].copy_from_slice(iv);
    hmac_input[ID_LEN + PIN_LEN + IV_LEN..].copy_from_slice(partition_nonce);
    if !pal.hmac_verify(hmac_key, &hmac_input, tag).await? {
        return Err(HsmError::PinDecryptionFailed);
    }

    // 4. AES-CBC decrypt encrypted_id with iv. The PAL updates the IV
    //    in-place to the last ciphertext block, which is the input to
    //    decrypting encrypted_pin.
    let mut iv_chain = [0u8; IV_LEN];
    iv_chain.copy_from_slice(iv);
    let mut id = [0u8; ID_LEN];
    pal.aes_cbc_enc_dec(aes_key, false, &mut iv_chain, encrypted_id, &mut id)
        .await?;

    // 5. AES-CBC decrypt encrypted_pin with the chained IV.
    let mut pin = [0u8; PIN_LEN];
    pal.aes_cbc_enc_dec(aes_key, false, &mut iv_chain, encrypted_pin, &mut pin)
        .await?;

    Ok((id, pin))
}

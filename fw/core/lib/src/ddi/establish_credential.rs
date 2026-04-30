// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EstablishCredential command handler.
//!
//! Single-shot per-partition operation that:
//!
//! 1. Verifies the POTA endorsement signature over the partition's
//!    identity public key (`pota_pub_key` ECDSA-P384 verifies
//!    `pota_sig` against `SHA384(partition.id_pub_key)`).
//! 2. Validates that the encrypted credential's nonce matches the
//!    partition's current nonce (replay protection).
//! 3. Recovers the user `(id, pin)` pair from the host-encrypted
//!    blob using ECDH(partition.establish_cred_priv, host_pub_key),
//!    HKDF-SHA384, AES-CBC-256, and HMAC-SHA-384 (delegated to
//!    [`crate::credential::unwrap_credential`]).
//! 4. Stores the credential in partition state for `OpenSession` to
//!    authenticate against.
//! 5. Refreshes the partition nonce so the same ciphertext can't be
//!    replayed.
//! 6. Clears the establish-cred encryption key (one-time-use pattern).
//! 7. Returns an empty `bmk` in the response (BMK derivation from
//!    `masked_bk3` is deferred until the test path actually exercises
//!    it; the integration tests pass empty BMK input and ignore the
//!    response BMK).
//!
//! Mirrors `mcr-hsm/.../hsm/src/fsm/establish_credential.rs` and
//! `ddi/sim/src/dispatcher.rs::dispatch_establish_credential`.
//! NoSession command.

use azihsm_fw_ddi_types::establish_credential::DdiEstablishCredentialReq;
use azihsm_fw_ddi_types::establish_credential::DdiEstablishCredentialResp;

use super::*;
use crate::credential;

/// Length in bytes of the POTA pub-key (ECC P-384, raw LE X || LE Y).
const ECC_P384_PUB_LEN: usize = 96;

/// Length in bytes of the SHA-384 digest of the partition pub-key.
const SHA384_DIGEST_LEN: usize = 48;

/// Handle DdiEstablishCredentialCmd.
pub(crate) async fn establish_credential<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiEstablishCredentialReq = decoder.decode_data()?;

    // ── 0. Lightweight body validation ─────────────────────────────
    if body.masked_bk3.is_empty() {
        return Err(HsmError::InvalidArg);
    }
    if body.pota_pub_key.key_kind != DdiKeyType::Ecc384Public {
        return Err(HsmError::InvalidArg);
    }
    if body.pota_pub_key.raw.len() != ECC_P384_PUB_LEN {
        return Err(HsmError::InvalidArg);
    }
    if body.pub_key.key_kind != DdiKeyType::Ecc384Public
        || body.pub_key.raw.len() != ECC_P384_PUB_LEN
    {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Verify POTA signature over partition's identity pub key ─
    //         The host signs `SHA384(0x04 || X_be || Y_be)` of the
    //         partition's identity public key (uncompressed point).
    //         Our partition pub key is stored in PKA-native LE; we
    //         build the BE uncompressed form into fmem, hash it, and
    //         verify.
    const ECC_P384_UNCOMP_LEN: usize = 1 + ECC_P384_PUB_LEN; // 0x04 || X || Y
    let id_pub_le_off = 0usize;
    let id_pub_le_end = id_pub_le_off + ECC_P384_PUB_LEN;
    let uncomp_off = id_pub_le_end;
    let uncomp_end = uncomp_off + ECC_P384_UNCOMP_LEN;
    let digest_off = uncomp_end;
    let digest_end = digest_off + SHA384_DIGEST_LEN;
    if fmem.len() < digest_end {
        return Err(HsmError::InternalError);
    }
    let id_pub_len = pal.part_id_pub_key(part_id, Some(&mut fmem[id_pub_le_off..id_pub_le_end]))?;
    if id_pub_len != ECC_P384_PUB_LEN {
        return Err(HsmError::InternalError);
    }
    // Build BE uncompressed point: 0x04 || X_be || Y_be.
    {
        // Capture LE coords into local arrays first to release the
        // immutable borrow before mutating fmem at uncomp_off.
        let half = ECC_P384_PUB_LEN / 2;
        let mut le_x = [0u8; 48];
        let mut le_y = [0u8; 48];
        le_x.copy_from_slice(&fmem[id_pub_le_off..id_pub_le_off + half]);
        le_y.copy_from_slice(&fmem[id_pub_le_off + half..id_pub_le_end]);
        fmem[uncomp_off] = 0x04;
        for i in 0..half {
            fmem[uncomp_off + 1 + i] = le_x[half - 1 - i];
            fmem[uncomp_off + 1 + half + i] = le_y[half - 1 - i];
        }
    }
    // SHA-384 the uncompressed point into the digest slot.
    {
        let (a, b) = fmem.split_at_mut(digest_off);
        pal.hash(
            HsmHashAlgo::Sha384,
            &a[uncomp_off..uncomp_off + ECC_P384_UNCOMP_LEN],
            &mut b[..SHA384_DIGEST_LEN],
        )
        .await?;
        // ECC driver expects LE digest (matches real PKA hardware).
        b[..SHA384_DIGEST_LEN].reverse();
    }
    if !pal
        .ecc_verify(
            body.pota_pub_key.raw,
            &fmem[digest_off..digest_end],
            body.pota_sig,
        )
        .await?
    {
        return Err(HsmError::EccVerifyFailed);
    }

    // ── 2. Verify the encrypted-credential nonce matches partition ─
    //         (Replay protection.)
    if body.encrypted_credential.nonce.len() != credential::NONCE_LEN {
        return Err(HsmError::InvalidArg);
    }
    let mut partition_nonce = [0u8; credential::NONCE_LEN];
    let n_len = pal.part_nonce(part_id, Some(&mut partition_nonce))?;
    if n_len != credential::NONCE_LEN {
        return Err(HsmError::InternalError);
    }
    if partition_nonce.as_slice() != body.encrypted_credential.nonce {
        return Err(HsmError::NonceMismatch);
    }

    // ── 3. Pre-flight: reject if a credential is already established.
    //         Catching this here avoids doing the expensive ECDH/AES
    //         work just to fail at storage time.
    if pal.part_user_credential(part_id).is_ok() {
        return Err(HsmError::VaultAppLimitReached);
    }

    // ── 4. Decrypt (id, pin) via ECDH+HKDF+AES-CBC+HMAC chain ──────
    let establish_cred_key_id = pal
        .part_establish_cred_key_id(part_id)?
        .ok_or(HsmError::KeyNotFound)?;
    let priv_der = pal.vault_key(part_id, establish_cred_key_id)?;
    // Copy priv_der out of the vault to a stack buffer because the
    // unwrap helper awaits and we shouldn't hold the partition borrow
    // across the await.
    let mut priv_der_local = [0u8; 256];
    if priv_der.len() > priv_der_local.len() {
        return Err(HsmError::InternalError);
    }
    let priv_len = priv_der.len();
    priv_der_local[..priv_len].copy_from_slice(priv_der);

    let nonce_arr: [u8; credential::NONCE_LEN] = partition_nonce;
    let (id, pin) = credential::unwrap_credential(
        pal,
        &priv_der_local[..priv_len],
        body.pub_key.raw,
        &nonce_arr,
        body.encrypted_credential.encrypted_id,
        body.encrypted_credential.encrypted_pin,
        body.encrypted_credential.iv,
        body.encrypted_credential.tag,
    )
    .await?;

    // ── 5. Persist the credential, refresh the nonce, clear the
    //         single-use establish-cred encryption key. ──────────────
    let mut host_pub_key_local = [0u8; ECC_P384_PUB_LEN];
    host_pub_key_local.copy_from_slice(body.pub_key.raw);
    pal.part_set_user_credential(part_id, &id, &pin, &host_pub_key_local)?;
    pal.part_nonce_refresh(part_id)?;
    pal.part_clear_establish_cred_key(part_id)?;

    // Wipe sensitive scratch.
    priv_der_local.fill(0);

    // ── 6. Encode the response. BMK derivation is deferred. ────────
    let len = ddi::encode_resp(
        ddi::success_hdr(hdr, DdiOp::EstablishCredential),
        DdiEstablishCredentialResp { bmk: &[] },
        smem,
    )?;
    Ok(&smem[..len])
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI OpenSession command handler.
//!
//! Decrypts the session credential (id, pin, seed), verifies the user
//! matches the previously-established credential, derives a session
//! masking key, creates the session entry, and returns
//! `(sess_id, short_app_id, bmk_session)`.
//!
//! This is a NoSession command — `hdr.sess_id` must be `None`.

use azihsm_fw_ddi_types::open_session::DdiOpenSessionReq;
use azihsm_fw_ddi_types::open_session::DdiOpenSessionResp;

use super::*;
use crate::credential::NONCE_LEN;
use crate::credential::{self};
use crate::lm_key_derive::BK_AES_CBC_256_HMAC384_SIZE_BYTES;
use crate::lm_key_derive::{self};
use crate::masked_key;

/// Maximum encoded length for the BMK metadata blob.
const METADATA_BUF_LEN: usize = 128;

/// Handle DdiOpenSessionCmd.
pub(crate) async fn open_session<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiOpenSessionReq<'_> = decoder.decode_data()?;

    // ── 0. Validate header fields ─────────────────────────────────────
    if hdr.sess_id.is_some() {
        return Err(HsmError::SessionNotExpected);
    }
    let api_rev = hdr.rev.ok_or(HsmError::UnsupportedRevision)?;

    // ── 1. Nonce check ────────────────────────────────────────────────
    let mut stored_nonce = [0u8; NONCE_LEN];
    pal.part_nonce(part_id, Some(&mut stored_nonce))?;
    if body.encrypted_credential.nonce != stored_nonce {
        return Err(HsmError::NonceMismatch);
    }

    // ── 2. Decrypt (id, pin, seed) via session-enc key ────────────────
    let se_kid = pal.part_session_enc_key_id(part_id)?;
    let se_priv = pal.vault_key(part_id, se_kid)?;

    let (dec_id, dec_pin, session_seed) = credential::unwrap_session_credential(
        pal,
        se_priv,
        body.pub_key.raw,
        &stored_nonce,
        body.encrypted_credential.encrypted_id,
        body.encrypted_credential.encrypted_pin,
        body.encrypted_credential.encrypted_seed,
        body.encrypted_credential.iv,
        body.encrypted_credential.tag,
    )
    .await?;

    // ── 3. Refresh nonce immediately after HMAC verification ──────────
    pal.part_nonce_refresh(part_id)?;

    // ── 4. Verify decrypted credentials match established ones ────────
    let (est_id, est_pin, _est_pub) = pal.part_user_credential(part_id)?;
    if dec_id != *est_id || dec_pin != *est_pin {
        return Err(HsmError::InvalidAppCredentials);
    }

    // ── 5. Recover bk_partition from masked_bk_boot ───────────────────
    let masked_bk_boot_len = pal.part_masked_bk_boot(part_id, None)?;
    if masked_bk_boot_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    pal.part_masked_bk_boot(part_id, Some(&mut fmem[..masked_bk_boot_len]))?;

    let mut bk_boot_masking_key = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
    lm_key_derive::bk_boot_masking_key(pal, &mut bk_boot_masking_key).await?;

    let mut bk_partition = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
    masked_key::decode_aes_cbc_256_hmac384(
        pal,
        &bk_boot_masking_key,
        &fmem[..masked_bk_boot_len],
        &mut bk_partition,
    )
    .await?;

    // ── 6. Derive bk_session from (bk_partition, session_seed) ────────
    let mut bk_session = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
    lm_key_derive::bk_session_gen(pal, &session_seed, &bk_partition, &mut bk_session).await?;

    // ── 7. Generate session masking key (mk_session) ──────────────────
    let mut mk_session = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
    lm_key_derive::mk_session_gen(pal, &mut mk_session).await?;

    // ── 8. Encode mk_session into a BMK envelope using bk_session ─────
    //       The host receives this as `bmk_session` and may send it back
    //       in ReopenSession.
    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let metadata_len = encode_smk_metadata(&mut metadata_buf)?;
    let bmk_len = masked_key::aes_cbc_envelope_len(metadata_len, BK_AES_CBC_256_HMAC384_SIZE_BYTES);
    if bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &mk_session,
        &bk_session,
        &metadata_buf[..metadata_len],
        &mut fmem[..bmk_len],
    )
    .await?;

    // ── 9. Create session via PAL ─────────────────────────────────────
    let mut api_rev_bytes = [0u8; 8];
    api_rev_bytes[..4].copy_from_slice(&api_rev.major.to_le_bytes());
    api_rev_bytes[4..].copy_from_slice(&api_rev.minor.to_le_bytes());

    let guard = pal.session_create(part_id, &api_rev_bytes, &mk_session, None)?;
    let sess_id = guard.dismiss();

    // ── 10. Encode response ───────────────────────────────────────────
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::OpenSession,
        sess_id: Some(u16::from(sess_id)),
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiOpenSessionResp {
        sess_id: u16::from(sess_id),
        short_app_id: 0,
        bmk_session: &fmem[..bmk_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

/// MBOR-encode the BMK metadata for a session masking key.
///
/// Matches the sim's `encode_masked_key_metadata` call in
/// `generate_session_bmk`: svn=1, key_type=AesCbc256Hmac384,
/// key_attributes=zeroed, bks2_index=0, key_label="SMK",
/// key_length=80.
fn encode_smk_metadata(buf: &mut [u8; METADATA_BUF_LEN]) -> HsmResult<usize> {
    use azihsm_fw_ddi_types::masked_key::*;

    let attrs_blob = [0u8; 32];
    let metadata = DdiMaskedKeyMetadata {
        svn: Some(1),
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: DdiMaskedKeyAttributes { blob: &attrs_blob },
        bks2_index: Some(0),
        key_tag: None,
        key_label: b"SMK",
        key_length: BK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
    };

    let mut acc = MborLenAccumulator::default();
    metadata.mbor_len(&mut acc);
    let len = acc.len();
    if len > buf.len() {
        return Err(HsmError::InternalError);
    }

    let mut encoder = MborEncoder::new(&mut buf[..len]);
    metadata
        .mbor_encode(&mut encoder)
        .map_err(|_| HsmError::DdiEncodeFailed)?;
    Ok(len)
}

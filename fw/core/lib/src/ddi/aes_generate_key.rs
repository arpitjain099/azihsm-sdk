// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI AesGenerateKey command handler.
//!
//! Generates a random AES key, stores it in the partition vault, masks
//! the key with the session masking key (or partition masking key for
//! persistent keys), and returns the masked blob to the host.
//!
//! This is an in-session command — `hdr.sess_id` must be present.

use azihsm_fw_ddi_types::aes_generate_key::DdiAesGenerateKeyReq;
use azihsm_fw_ddi_types::aes_generate_key::DdiAesGenerateKeyResp;
use azihsm_fw_ddi_types::masked_key::*;

use super::*;
use crate::masked_key;

// ── DdiTargetKeyMetadata bit-flag indices ─────────────────────────────
// Mirrors `ddi/serde/types/src/metadata.rs`.
const BIT_SESSION: usize = 0;
const BIT_ENCRYPT: usize = 2;
const BIT_DECRYPT: usize = 3;
const BIT_SIGN: usize = 4;
const BIT_VERIFY: usize = 5;
const BIT_DERIVE: usize = 6;
const BIT_UNWRAP: usize = 8;

fn meta_bit(blob: &[u8; 16], bit: usize) -> bool {
    let index = bit / 8;
    let shift = bit % 8;
    (blob[index] & (1 << shift)) != 0
}

/// Maximum encoded length for the masked-key metadata MBOR blob.
const METADATA_BUF_LEN: usize = 128;

/// Handle DdiAesGenerateKeyCmd.
pub(crate) async fn aes_generate_key<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiAesGenerateKeyReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let session_only = meta_bit(&body.key_properties.key_metadata.blob, BIT_SESSION);

    // Session-only keys cannot have a key_tag.
    if session_only && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Map DdiAesKeySize → vault key kind + byte length ───────────
    let (vault_kind, key_len) = match body.key_size {
        DdiAesKeySize::Aes128 => (HsmVaultKeyKind::Aes128, 16usize),
        DdiAesKeySize::Aes192 => (HsmVaultKeyKind::Aes192, 24),
        DdiAesKeySize::Aes256 => (HsmVaultKeyKind::Aes256, 32),
        _ => return Err(HsmError::InvalidArg),
    };

    // ── 2. Parse key usage from metadata bitflags ─────────────────────
    let md = &body.key_properties.key_metadata.blob;
    let mut attrs = HsmVaultKeyAttrs::new();
    if meta_bit(md, BIT_ENCRYPT) && meta_bit(md, BIT_DECRYPT) {
        attrs = attrs.with_encrypt(true).with_decrypt(true);
    } else if meta_bit(md, BIT_SIGN) && meta_bit(md, BIT_VERIFY) {
        attrs = attrs.with_sign(true).with_verify(true);
    } else if meta_bit(md, BIT_UNWRAP) {
        attrs = attrs.with_unwrap(true);
    } else if meta_bit(md, BIT_DERIVE) {
        return Err(HsmError::InvalidPermissions);
    } else {
        return Err(HsmError::InvalidArg);
    }

    if session_only {
        attrs = attrs.with_session(true);
    }

    // ── 3. Generate random AES key bytes ──────────────────────────────
    if key_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    pal.rng_fill_bytes(&mut fmem[..key_len])?;

    // ── 4. Store key in vault ─────────────────────────────────────────
    let session_id_for_vault = if session_only {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let guard = pal.vault_key_create(
        part_id,
        &fmem[..key_len],
        vault_kind,
        session_id_for_vault,
        attrs,
        body.key_properties.key_metadata.blob.as_slice(),
    )?;
    let key_id = guard.dismiss();

    // ── 5. Build masking key from session ─────────────────────────────
    let masking_key = pal.session_masking_key(part_id, HsmSessId::from(sess_id))?;

    // ── 6. Encode metadata MBOR ───────────────────────────────────────
    let sess_id_or_key_tag: u16 = if session_only {
        sess_id
    } else {
        body.key_tag.unwrap_or(0)
    };
    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let metadata_len = encode_key_metadata(
        &mut metadata_buf,
        vault_kind,
        &body.key_properties.key_metadata.blob,
        sess_id_or_key_tag,
        body.key_tag,
        key_len as u16,
    )?;

    // ── 7. Encode masked key ──────────────────────────────────────────
    // The masked-key encoder requires the plaintext to be a multiple of
    // AES_BLOCK_SIZE (16). For AES-192 (24 bytes) we must zero-pad.
    let padded_key_len = key_len.next_multiple_of(16);
    let bmk_len = masked_key::aes_cbc_envelope_len(metadata_len, padded_key_len);
    // Use a region of fmem after the plaintext key bytes.
    let bmk_off = padded_key_len;
    if bmk_off + bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }

    // Copy plaintext key to a local array, zero-padded to block size.
    let mut pt_key = [0u8; 32];
    pt_key[..key_len].copy_from_slice(&fmem[..key_len]);

    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &pt_key[..padded_key_len],
        masking_key,
        &metadata_buf[..metadata_len],
        &mut fmem[bmk_off..bmk_off + bmk_len],
    )
    .await?;

    // ── 8. Determine bulk_key_id ──────────────────────────────────────
    let is_bulk = matches!(
        body.key_size,
        DdiAesKeySize::AesXtsBulk256
            | DdiAesKeySize::AesGcmBulk256
            | DdiAesKeySize::AesGcmBulk256Unapproved
    );
    let bulk_key_id = if is_bulk {
        Some(u16::from(key_id))
    } else {
        None
    };

    // ── 9. Encode response ────────────────────────────────────────────
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::AesGenerateKey,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiAesGenerateKeyResp {
        key_id: u16::from(key_id),
        bulk_key_id,
        masked_key: &fmem[bmk_off..bmk_off + bmk_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

/// MBOR-encode the masked-key metadata for a vault key.
///
/// Matches the sim's `mask_vault_entry` metadata layout:
/// - `key_attributes.blob[0..8]` = entry flags as u64 LE
/// - `key_attributes.blob[8..10]` = sess_id_or_key_tag as u16 LE
/// - rest zeroed (app_id not available in fw side)
fn encode_key_metadata(
    buf: &mut [u8; METADATA_BUF_LEN],
    vault_kind: HsmVaultKeyKind,
    target_meta: &[u8; 16],
    sess_id_or_key_tag: u16,
    key_tag: Option<u16>,
    key_length: u16,
) -> HsmResult<usize> {
    let mut attrs_blob = [0u8; 32];
    // Pack entry flags from target key metadata into the attributes blob.
    // The sim packs u64::from(entry.flags()) at offset 0.
    // We approximate by copying the 16-byte DdiTargetKeyMetadata blob
    // into the first 16 bytes (the sim only reads back bytes 0..8 as
    // flags, 8..10 as sess_id_or_key_tag, 10..26 as app_id).
    attrs_blob[..16].copy_from_slice(target_meta);
    attrs_blob[8..10].copy_from_slice(&sess_id_or_key_tag.to_le_bytes());

    let ddi_key_type = match vault_kind {
        HsmVaultKeyKind::Aes128 => DdiKeyType::Aes128,
        HsmVaultKeyKind::Aes192 => DdiKeyType::Aes192,
        HsmVaultKeyKind::Aes256 => DdiKeyType::Aes256,
        _ => return Err(HsmError::InvalidArg),
    };

    let metadata = DdiMaskedKeyMetadata {
        svn: Some(1),
        key_type: ddi_key_type,
        key_attributes: DdiMaskedKeyAttributes { blob: &attrs_blob },
        bks2_index: None,
        key_tag,
        key_label: b"",
        key_length,
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

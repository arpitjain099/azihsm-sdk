// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI HkdfDerive and KbkdfCounterHmacDerive command handlers.
//!
//! Both derive a new key from a vault-stored secret (Secret256/384/521)
//! using the PAL's HKDF or KBKDF primitive, store the derived key in
//! the vault, mask it, and return the masked blob.
//!
//! These are in-session commands.

use azihsm_fw_ddi_types::derive_hkdf::DdiHkdfDeriveReq;
use azihsm_fw_ddi_types::derive_hkdf::DdiHkdfDeriveResp;
use azihsm_fw_ddi_types::derive_kbkdf::DdiKbkdfCounterHmacDeriveReq;
use azihsm_fw_ddi_types::derive_kbkdf::DdiKbkdfCounterHmacDeriveResp;
use azihsm_fw_ddi_types::masked_key::*;

use super::*;
use crate::ddi::aes_generate_key::meta_bit;
use crate::ddi::aes_generate_key::BIT_SESSION;
use crate::masked_key;

const METADATA_BUF_LEN: usize = 128;

/// Map DdiKeyType → (HsmVaultKeyKind, output byte length).
fn output_key_info(key_type: DdiKeyType) -> HsmResult<(HsmVaultKeyKind, usize)> {
    match key_type {
        DdiKeyType::Aes128 => Ok((HsmVaultKeyKind::Aes128, 16)),
        DdiKeyType::Aes192 => Ok((HsmVaultKeyKind::Aes192, 24)),
        DdiKeyType::Aes256 => Ok((HsmVaultKeyKind::Aes256, 32)),
        DdiKeyType::HmacSha256 => Ok((HsmVaultKeyKind::_HmacSha256, 32)),
        DdiKeyType::HmacSha384 => Ok((HsmVaultKeyKind::_HmacSha384, 48)),
        DdiKeyType::HmacSha512 => Ok((HsmVaultKeyKind::_HmacSha512, 64)),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Map DdiHashAlgorithm → HsmHashAlgo.
fn map_hash_algo(algo: DdiHashAlgorithm) -> HsmResult<HsmHashAlgo> {
    match algo {
        DdiHashAlgorithm::Sha256 => Ok(HsmHashAlgo::Sha256),
        DdiHashAlgorithm::Sha384 => Ok(HsmHashAlgo::Sha384),
        DdiHashAlgorithm::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle DdiHkdfDeriveCmd.
pub(crate) async fn hkdf_derive<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiHkdfDeriveReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let session_only = meta_bit(&body.key_properties.key_metadata.blob, BIT_SESSION);

    if session_only && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }
    if body.key_tag == Some(0) {
        return Err(HsmError::InvalidArg);
    }

    // Validate source key is a Secret with Derive permission.
    let src_kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.key_id))?;
    match src_kind {
        HsmVaultKeyKind::Secret256 | HsmVaultKeyKind::Secret384 | HsmVaultKeyKind::Secret521 => {}
        _ => return Err(HsmError::InvalidKeyType),
    }
    let src_attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if !src_attrs.derive() {
        return Err(HsmError::InvalidPermissions);
    }

    let (out_kind, out_len) = output_key_info(body.key_type)?;
    let hash_algo = map_hash_algo(body.hash_algorithm)?;

    // Get source key bytes and derive.
    let src_key = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;
    if out_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    let salt = body.salt.unwrap_or(&[]);
    let info = body.info.unwrap_or(&[]);
    pal.hkdf(
        src_key,
        hash_algo,
        HkdfMode::ExtractAndExpand,
        salt,
        info,
        &mut fmem[..out_len],
    )
    .await?;

    // Store + mask + respond (shared logic).
    derive_store_mask_respond(
        hdr,
        DdiOp::HkdfDerive,
        sess_id,
        session_only,
        part_id,
        pal,
        fmem,
        smem,
        out_kind,
        out_len,
        body.key_type,
        &body.key_properties.key_metadata.blob,
        body.key_tag,
    )
    .await
}

/// Handle DdiKbkdfCounterHmacDeriveCmd.
pub(crate) async fn kbkdf_counter_hmac_derive<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiKbkdfCounterHmacDeriveReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let session_only = meta_bit(&body.key_properties.key_metadata.blob, BIT_SESSION);

    if session_only && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }
    if body.key_tag == Some(0) {
        return Err(HsmError::InvalidArg);
    }

    let src_kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.key_id))?;
    match src_kind {
        HsmVaultKeyKind::Secret256 | HsmVaultKeyKind::Secret384 | HsmVaultKeyKind::Secret521 => {}
        _ => return Err(HsmError::InvalidKeyType),
    }
    let src_attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if !src_attrs.derive() {
        return Err(HsmError::InvalidPermissions);
    }

    let (out_kind, out_len) = output_key_info(body.key_type)?;
    let hash_algo = map_hash_algo(body.hash_algorithm)?;

    let src_key = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;
    if out_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    let label = body.label.unwrap_or(&[]);
    let context = body.context.unwrap_or(&[]);
    pal.kbkdf(src_key, hash_algo, label, context, &mut fmem[..out_len])
        .await?;

    derive_store_mask_respond(
        hdr,
        DdiOp::KbkdfCounterHmacDerive,
        sess_id,
        session_only,
        part_id,
        pal,
        fmem,
        smem,
        out_kind,
        out_len,
        body.key_type,
        &body.key_properties.key_metadata.blob,
        body.key_tag,
    )
    .await
}

/// Shared tail: store derived key in vault, mask, encode response.
#[allow(clippy::too_many_arguments)]
async fn derive_store_mask_respond<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    op: DdiOp,
    sess_id: u16,
    session_only: bool,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
    out_kind: HsmVaultKeyKind,
    out_len: usize,
    ddi_key_type: DdiKeyType,
    target_meta: &[u8; 16],
    key_tag: Option<u16>,
) -> HsmResult<&'a [u8]> {
    let mut attrs = HsmVaultKeyAttrs::new().with_local(true);
    // For derived keys, inherit usage from metadata bitflags.
    use crate::ddi::aes_generate_key::*;
    let md = target_meta;
    if meta_bit(md, BIT_ENCRYPT) && meta_bit(md, BIT_DECRYPT) {
        attrs = attrs.with_encrypt(true).with_decrypt(true);
    } else if meta_bit(md, BIT_SIGN) && meta_bit(md, BIT_VERIFY) {
        attrs = attrs.with_sign(true).with_verify(true);
    } else if meta_bit(md, BIT_UNWRAP) {
        attrs = attrs.with_unwrap(true);
    } else if meta_bit(md, BIT_DERIVE) {
        attrs = attrs.with_derive(true);
    } else {
        return Err(HsmError::InvalidArg);
    }
    if session_only {
        attrs = attrs.with_session(true);
    }

    let session_id_for_vault = if session_only {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let guard = pal.vault_key_create(
        part_id,
        &fmem[..out_len],
        out_kind,
        session_id_for_vault,
        attrs,
        target_meta.as_slice(),
    )?;
    let key_id = guard.dismiss();

    // Mask the derived key.
    let masking_key = pal.session_masking_key(part_id, HsmSessId::from(sess_id))?;

    let sess_id_or_key_tag: u16 = if session_only {
        sess_id
    } else {
        key_tag.unwrap_or(0)
    };
    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let metadata_len = {
        let mut attrs_blob = [0u8; 32];
        attrs_blob[..16].copy_from_slice(target_meta);
        attrs_blob[8..10].copy_from_slice(&sess_id_or_key_tag.to_le_bytes());

        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: ddi_key_type,
            key_attributes: DdiMaskedKeyAttributes { blob: &attrs_blob },
            bks2_index: None,
            key_tag,
            key_label: b"",
            key_length: out_len as u16,
        };

        let mut acc = MborLenAccumulator::default();
        metadata.mbor_len(&mut acc);
        let len = acc.len();
        if len > metadata_buf.len() {
            return Err(HsmError::InternalError);
        }
        let mut encoder = MborEncoder::new(&mut metadata_buf[..len]);
        metadata
            .mbor_encode(&mut encoder)
            .map_err(|_| HsmError::DdiEncodeFailed)?;
        len
    };

    let padded_len = out_len.next_multiple_of(16);
    let bmk_len = masked_key::aes_cbc_envelope_len(metadata_len, padded_len);
    let bmk_off = out_len;
    if bmk_off + bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    let mut pt_key = [0u8; 80];
    pt_key[..out_len].copy_from_slice(&fmem[..out_len]);

    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &pt_key[..padded_len],
        masking_key,
        &metadata_buf[..metadata_len],
        &mut fmem[bmk_off..bmk_off + bmk_len],
    )
    .await?;

    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };

    // Both HkdfDeriveResp and KbkdfCounterHmacDeriveResp have the
    // same wire layout: key_id(1), masked_key(2), bulk_key_id(3).
    // Use HkdfDeriveResp for both.
    let resp_data = DdiHkdfDeriveResp {
        key_id: u16::from(key_id),
        masked_key: &fmem[bmk_off..bmk_off + bmk_len],
        bulk_key_id: None,
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

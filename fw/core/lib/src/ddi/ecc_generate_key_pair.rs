// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccGenerateKeyPair command handler.
//!
//! Generates an ECC key pair, stores the PKCS#8 DER private key in the
//! vault, masks it, and returns the public key (raw LE) + masked blob.
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::ecc_generate_key_pair::DdiEccGenerateKeyPairReq;
use azihsm_fw_ddi_types::ecc_generate_key_pair::DdiEccGenerateKeyPairResp;
use azihsm_fw_ddi_types::masked_key::*;

use super::*;
use crate::ddi::aes_generate_key::meta_bit;
use crate::ddi::aes_generate_key::BIT_DECRYPT;
use crate::ddi::aes_generate_key::BIT_DERIVE;
use crate::ddi::aes_generate_key::BIT_ENCRYPT;
use crate::ddi::aes_generate_key::BIT_SESSION;
use crate::ddi::aes_generate_key::BIT_SIGN;
use crate::ddi::aes_generate_key::BIT_UNWRAP;
use crate::ddi::aes_generate_key::BIT_VERIFY;
use crate::masked_key;

/// Maximum encoded length for the masked-key metadata MBOR blob.
const METADATA_BUF_LEN: usize = 128;

/// Handle DdiEccGenerateKeyPairCmd.
pub(crate) async fn ecc_generate_key_pair<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiEccGenerateKeyPairReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let session_only = meta_bit(&body.key_properties.key_metadata.blob, BIT_SESSION);

    if session_only && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Map DdiEccCurve → HsmEccCurve + vault key kind ────────────
    let (hsm_curve, vault_kind, ddi_key_type) = match body.curve {
        DdiEccCurve::P256 => (
            HsmEccCurve::P256,
            HsmVaultKeyKind::Ecc256Private,
            DdiKeyType::Ecc256Public,
        ),
        DdiEccCurve::P384 => (
            HsmEccCurve::P384,
            HsmVaultKeyKind::Ecc384Private,
            DdiKeyType::Ecc384Public,
        ),
        DdiEccCurve::P521 => (
            HsmEccCurve::P521,
            HsmVaultKeyKind::Ecc521Private,
            DdiKeyType::Ecc521Public,
        ),
        _ => return Err(HsmError::InvalidArg),
    };
    let pub_key_len = hsm_curve.pub_key_len();

    // ── 2. Validate key usage ─────────────────────────────────────────
    // ECC keys allow SignVerify or Derive only.
    let md = &body.key_properties.key_metadata.blob;
    let mut attrs = HsmVaultKeyAttrs::new();
    if meta_bit(md, BIT_SIGN)
        && meta_bit(md, BIT_VERIFY)
        && !meta_bit(md, BIT_ENCRYPT)
        && !meta_bit(md, BIT_DECRYPT)
        && !meta_bit(md, BIT_DERIVE)
        && !meta_bit(md, BIT_UNWRAP)
    {
        attrs = attrs.with_sign(true).with_verify(true);
    } else if meta_bit(md, BIT_DERIVE)
        && !meta_bit(md, BIT_SIGN)
        && !meta_bit(md, BIT_VERIFY)
        && !meta_bit(md, BIT_ENCRYPT)
        && !meta_bit(md, BIT_DECRYPT)
        && !meta_bit(md, BIT_UNWRAP)
    {
        attrs = attrs.with_derive(true);
    } else {
        return Err(HsmError::InvalidPermissions);
    }

    attrs = attrs.with_local(true);
    if session_only {
        attrs = attrs.with_session(true);
    }

    // ── 3. Generate ECC key pair ──────────────────────────────────────
    let priv_der_max = hsm_curve.priv_key_der_max();
    if priv_der_max > fmem.len() {
        return Err(HsmError::InternalError);
    }

    // The driver produces PKA-native pub key (4-byte aligned coords).
    let mut pub_buf = [0u8; 136]; // max PKA size: 68*2 for P-521
    let priv_der_len = pal
        .ecc_gen_keypair(
            hsm_curve,
            Some(&mut fmem[..priv_der_max]),
            &mut pub_buf[..pub_key_len],
            HsmEccPct::SignVerify,
        )
        .await?;

    // ── 4. Store private key DER in vault ─────────────────────────────
    let session_id_for_vault = if session_only {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let guard = pal.vault_key_create(
        part_id,
        &fmem[..priv_der_len],
        vault_kind,
        session_id_for_vault,
        attrs,
        body.key_properties.key_metadata.blob.as_slice(),
    )?;
    let key_id = guard.dismiss();

    // ── 5. Mask the private key ───────────────────────────────────────
    let masking_key = pal.session_masking_key(part_id, HsmSessId::from(sess_id))?;

    let sess_id_or_key_tag: u16 = if session_only {
        sess_id
    } else {
        body.key_tag.unwrap_or(0)
    };
    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let metadata_len = encode_ecc_metadata(
        &mut metadata_buf,
        vault_kind,
        &body.key_properties.key_metadata.blob,
        sess_id_or_key_tag,
        body.key_tag,
        priv_der_len as u16,
    )?;

    let padded_priv_len = priv_der_len.next_multiple_of(16);
    let bmk_len = masked_key::aes_cbc_envelope_len(metadata_len, padded_priv_len);

    // We need scratch for: priv DER (priv_der_len) + bmk (bmk_len).
    // Place the BMK after the priv region.
    let bmk_off = priv_der_max;
    if bmk_off + bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }

    // Copy priv DER into a local array, zero-padded to block boundary.
    let mut pt_key = [0u8; 256]; // priv_key_der_max for P-521 is 241
    pt_key[..priv_der_len].copy_from_slice(&fmem[..priv_der_len]);

    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &pt_key[..padded_priv_len],
        masking_key,
        &metadata_buf[..metadata_len],
        &mut fmem[bmk_off..bmk_off + bmk_len],
    )
    .await?;

    // ── 6. Encode response ────────────────────────────────────────────
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::EccGenerateKeyPair,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiEccGenerateKeyPairResp {
        private_key_id: u16::from(key_id),
        pub_key: DdiPublicKey {
            raw: &pub_buf[..pub_key_len],
            key_kind: ddi_key_type,
        },
        masked_key: &fmem[bmk_off..bmk_off + bmk_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

/// MBOR-encode the masked-key metadata for an ECC private key.
fn encode_ecc_metadata(
    buf: &mut [u8; METADATA_BUF_LEN],
    vault_kind: HsmVaultKeyKind,
    target_meta: &[u8; 16],
    sess_id_or_key_tag: u16,
    key_tag: Option<u16>,
    key_length: u16,
) -> HsmResult<usize> {
    let mut attrs_blob = [0u8; 32];
    attrs_blob[..16].copy_from_slice(target_meta);
    attrs_blob[8..10].copy_from_slice(&sess_id_or_key_tag.to_le_bytes());

    let ddi_key_type = match vault_kind {
        HsmVaultKeyKind::Ecc256Private => DdiKeyType::Ecc256Private,
        HsmVaultKeyKind::Ecc384Private => DdiKeyType::Ecc384Private,
        HsmVaultKeyKind::Ecc521Private => DdiKeyType::Ecc521Private,
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

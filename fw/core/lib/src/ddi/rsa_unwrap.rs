// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI RsaUnwrap command handler.
//!
//! Decrypts an RSA-AES-KW wrapped key blob using the partition's
//! unwrapping key, imports the decrypted key into the vault, masks
//! it, and returns the masked blob.
//!
//! Wire format: `RSA-OAEP(AES-KEK) || AES-KWP(target_key_der)`.
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::masked_key::*;
use azihsm_fw_ddi_types::rsa_unwrap::DdiRsaUnwrapReq;
use azihsm_fw_ddi_types::rsa_unwrap::DdiRsaUnwrapResp;

use super::*;
use crate::ddi::aes_generate_key::meta_bit;
use crate::ddi::aes_generate_key::BIT_SESSION;
use crate::masked_key;

const METADATA_BUF_LEN: usize = 128;

/// Handle DdiRsaUnwrapCmd.
pub(crate) async fn rsa_unwrap<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiRsaUnwrapReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let session_only = meta_bit(&body.key_properties.key_metadata.blob, BIT_SESSION);

    if session_only && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Validate unwrapping key ────────────────────────────────────
    let unwrap_attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if !unwrap_attrs.unwrap() {
        return Err(HsmError::InvalidPermissions);
    }

    // ── 2. RSA-AES-KW decrypt via PAL driver ─────────────────────────
    // Copy key DER to owned buffer — the vault borrow must not span
    // the async unwrap calls (UnsafeCell interior mutability).
    let unwrap_key_der = pal
        .vault_key(part_id, HsmKeyId::from(body.key_id))?
        .to_vec();

    let hash_algo = match body.wrapped_blob_hash_algorithm {
        DdiHashAlgorithm::Sha256 => HsmHashAlgo::Sha256,
        DdiHashAlgorithm::Sha384 => HsmHashAlgo::Sha384,
        _ => return Err(HsmError::InvalidArg),
    };

    // The host's `wrapped_blob_pre_encode` reversed the first 256 bytes
    // (RSA ciphertext) from BE to LE. Copy to a local buffer and
    // reverse them back to BE for the PAL's RSA-OAEP decrypt.
    let rsa_size = 256;
    let blob_len = body.wrapped_blob.len();
    if blob_len < rsa_size {
        return Err(HsmError::InvalidArg);
    }
    let mut blob = body.wrapped_blob.to_vec();
    blob[..rsa_size].reverse();

    let unwrapped_len = pal
        .rsa_aes_unwrap(&unwrap_key_der, hash_algo, &blob, None)
        .await?;
    if unwrapped_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    pal.rsa_aes_unwrap(
        &unwrap_key_der,
        hash_algo,
        &blob,
        Some(&mut fmem[..unwrapped_len]),
    )
    .await?;

    // ── 3. Determine key kind from unwrapped key via PAL ─────────────
    let is_crt = body.wrapped_blob_key_class == DdiKeyClass::RsaCrt;
    let key_size = pal.rsa_key_size(&fmem[..unwrapped_len])?;
    let (vault_kind, ddi_key_type, pub_ddi_type) = match (key_size, is_crt) {
        (256, false) => (
            HsmVaultKeyKind::Rsa2kPrivate,
            DdiKeyType::Rsa2kPrivate,
            DdiKeyType::Rsa2kPublic,
        ),
        (256, true) => (
            HsmVaultKeyKind::Rsa2kPrivateCrt,
            DdiKeyType::Rsa2kPrivateCrt,
            DdiKeyType::Rsa2kPublic,
        ),
        (384, false) => (
            HsmVaultKeyKind::Rsa3kPrivate,
            DdiKeyType::Rsa3kPrivate,
            DdiKeyType::Rsa3kPublic,
        ),
        (384, true) => (
            HsmVaultKeyKind::Rsa3kPrivateCrt,
            DdiKeyType::Rsa3kPrivateCrt,
            DdiKeyType::Rsa3kPublic,
        ),
        (512, false) => (
            HsmVaultKeyKind::Rsa4kPrivate,
            DdiKeyType::Rsa4kPrivate,
            DdiKeyType::Rsa4kPublic,
        ),
        (512, true) => (
            HsmVaultKeyKind::Rsa4kPrivateCrt,
            DdiKeyType::Rsa4kPrivateCrt,
            DdiKeyType::Rsa4kPublic,
        ),
        _ => return Err(HsmError::InvalidArg),
    };

    // Extract RSA public key SPKI DER for the response.
    let pub_der_len = pal.rsa_extract_pub_key(&fmem[..unwrapped_len], None)?;
    let mut pub_der = vec![0u8; pub_der_len];
    pal.rsa_extract_pub_key(&fmem[..unwrapped_len], Some(&mut pub_der))?;

    // ── 4. Store in vault ─────────────────────────────────────────────
    use crate::ddi::aes_generate_key::*;
    let md = &body.key_properties.key_metadata.blob;
    let mut attrs = HsmVaultKeyAttrs::new();
    if meta_bit(md, BIT_ENCRYPT) && meta_bit(md, BIT_DECRYPT) {
        attrs = attrs.with_encrypt(true).with_decrypt(true);
    } else if meta_bit(md, BIT_SIGN) && meta_bit(md, BIT_VERIFY) {
        attrs = attrs.with_sign(true).with_verify(true);
    } else if meta_bit(md, BIT_UNWRAP) {
        attrs = attrs.with_unwrap(true);
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
        &fmem[..unwrapped_len],
        vault_kind,
        session_id_for_vault,
        attrs,
        body.key_properties.key_metadata.blob.as_slice(),
    )?;
    let key_id = guard.dismiss();

    // ── 5. Mask the key ───────────────────────────────────────────────
    let masking_key = pal.session_masking_key(part_id, HsmSessId::from(sess_id))?;
    let sess_id_or_key_tag: u16 = if session_only {
        sess_id
    } else {
        body.key_tag.unwrap_or(0)
    };
    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let mut attrs_blob = [0u8; 32];
    attrs_blob[..16].copy_from_slice(body.key_properties.key_metadata.blob.as_slice());
    attrs_blob[8..10].copy_from_slice(&sess_id_or_key_tag.to_le_bytes());
    let metadata = DdiMaskedKeyMetadata {
        svn: Some(1),
        key_type: ddi_key_type,
        key_attributes: DdiMaskedKeyAttributes { blob: &attrs_blob },
        bks2_index: None,
        key_tag: body.key_tag,
        key_label: b"",
        key_length: unwrapped_len as u16,
    };
    let mut acc = MborLenAccumulator::default();
    metadata.mbor_len(&mut acc);
    let md_len = acc.len();
    let mut enc = MborEncoder::new(&mut metadata_buf[..md_len]);
    metadata
        .mbor_encode(&mut enc)
        .map_err(|_| HsmError::DdiEncodeFailed)?;

    let padded_len = unwrapped_len.next_multiple_of(16);
    let bmk_len = masked_key::aes_cbc_envelope_len(md_len, padded_len);
    let mut pt = vec![0u8; padded_len];
    pt[..unwrapped_len].copy_from_slice(&fmem[..unwrapped_len]);
    if bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &pt,
        masking_key,
        &metadata_buf[..md_len],
        &mut fmem[..bmk_len],
    )
    .await?;

    // ── 6. Encode response ────────────────────────────────────────────
    // Manual encoding because DdiRsaUnwrapResp has an optional pub_key
    // field and masked_key that needs careful handling.
    let resp_hdr = ddi::success_hdr(hdr, DdiOp::RsaUnwrap);
    let mut encoder = ddi::encode_resp_hdr(&resp_hdr, smem)?;

    // Count fields: key_id(1) + pub_key(2) + kind(4) + masked_key(5)
    MborMap(4).mbor_encode(&mut encoder)?;

    // Field 1: key_id.
    1u8.mbor_encode(&mut encoder)?;
    u16::from(key_id).mbor_encode(&mut encoder)?;

    // Field 2: pub_key (DdiPublicKey sub-map with SPKI DER).
    2u8.mbor_encode(&mut encoder)?;
    MborMap(2).mbor_encode(&mut encoder)?;
    1u8.mbor_encode(&mut encoder)?;
    MborByteSlice(&pub_der).mbor_encode(&mut encoder)?;
    2u8.mbor_encode(&mut encoder)?;
    pub_ddi_type.mbor_encode(&mut encoder)?;

    // Field 4: kind.
    4u8.mbor_encode(&mut encoder)?;
    ddi_key_type.mbor_encode(&mut encoder)?;

    // Field 5: masked_key.
    5u8.mbor_encode(&mut encoder)?;
    MborByteSlice(&fmem[..bmk_len]).mbor_encode(&mut encoder)?;

    let total = encoder.position();
    Ok(&smem[..total])
}

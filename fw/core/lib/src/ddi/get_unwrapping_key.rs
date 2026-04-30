// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetUnwrappingKey command handler.
//!
//! Returns the RSA-2k unwrapping key's ID, public key (raw LE), and
//! masked private key blob. The host uses this to encrypt (wrap)
//! private keys before importing them via `RsaUnwrap`.
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::get_unwrapping_key::DdiGetUnwrappingKeyReq;
use azihsm_fw_ddi_types::get_unwrapping_key::DdiGetUnwrappingKeyResp;
use azihsm_fw_ddi_types::masked_key::*;

use super::*;
use crate::masked_key;

const METADATA_BUF_LEN: usize = 128;

/// Handle DdiGetUnwrappingKeyCmd.
pub(crate) async fn get_unwrapping_key<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetUnwrappingKeyReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    let unwrap_kid = pal.part_unwrapping_key_id(part_id)?;
    let priv_der = pal.vault_key(part_id, unwrap_kid)?;

    // Get the public key DER length.
    let pub_der_len = pal.part_unwrapping_pub_key(part_id, None)?;

    // Mask the private key using the session masking key.
    let masking_key = pal.session_masking_key(part_id, HsmSessId::from(sess_id))?;

    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let attrs_blob = [0u8; 32];
    let metadata = DdiMaskedKeyMetadata {
        svn: Some(1),
        key_type: DdiKeyType::Rsa2kPrivate,
        key_attributes: DdiMaskedKeyAttributes { blob: &attrs_blob },
        bks2_index: None,
        key_tag: None,
        key_label: b"",
        key_length: priv_der.len() as u16,
    };
    let mut acc = MborLenAccumulator::default();
    metadata.mbor_len(&mut acc);
    let md_len = acc.len();
    if md_len > metadata_buf.len() {
        return Err(HsmError::InternalError);
    }
    let mut encoder = MborEncoder::new(&mut metadata_buf[..md_len]);
    metadata
        .mbor_encode(&mut encoder)
        .map_err(|_| HsmError::DdiEncodeFailed)?;

    let padded_priv_len = priv_der.len().next_multiple_of(16);
    let bmk_len = masked_key::aes_cbc_envelope_len(md_len, padded_priv_len);
    if bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }

    // Copy priv DER into local buffer for padding.
    let mut pt = vec![0u8; padded_priv_len];
    pt[..priv_der.len()].copy_from_slice(priv_der);

    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &pt,
        masking_key,
        &metadata_buf[..md_len],
        &mut fmem[..bmk_len],
    )
    .await?;

    // Build response with pub key in smem scratch area.
    // Use encode_resp_hdr + manual encoding to handle the pub key
    // DdiPublicKey (raw LE) correctly.
    let resp_hdr = ddi::success_hdr(hdr, DdiOp::GetUnwrappingKey);
    let mut enc = ddi::encode_resp_hdr(&resp_hdr, smem)?;

    // Data map: 3 fields.
    MborMap(3).mbor_encode(&mut enc)?;

    // Field 1: key_id (u16).
    1u8.mbor_encode(&mut enc)?;
    u16::from(unwrap_kid).mbor_encode(&mut enc)?;

    // Field 2: pub_key (DdiPublicKey sub-map).
    // For RSA, the "raw" public key is the SPKI DER.
    2u8.mbor_encode(&mut enc)?;
    MborMap(2).mbor_encode(&mut enc)?;
    1u8.mbor_encode(&mut enc)?;
    // Reserve space and fill pub key DER.
    let pub_slot = enc.encode_reserve(pub_der_len, 0)?;
    pal.part_unwrapping_pub_key(part_id, Some(pub_slot))?;
    2u8.mbor_encode(&mut enc)?;
    DdiKeyType::Rsa2kPublic.mbor_encode(&mut enc)?;

    // Field 3: masked_key (byte slice).
    3u8.mbor_encode(&mut enc)?;
    MborByteSlice(&fmem[..bmk_len]).mbor_encode(&mut enc)?;

    let total = enc.position();
    Ok(&smem[..total])
}

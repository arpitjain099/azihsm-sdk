// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Hmac command handler.
//!
//! Computes HMAC over a message using a vault-stored HMAC key.
//! The hash algorithm is determined by the key type
//! (HmacSha256/384/512).
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::hmac::DdiHmacReq;
use azihsm_fw_ddi_types::hmac::DdiHmacResp;

use super::*;

/// Handle DdiHmacCmd.
pub(crate) async fn hmac_op<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiHmacReq<'_> = decoder.decode_data()?;

    let _sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    if body.msg.is_empty() {
        return Err(HsmError::InvalidArg);
    }

    // Validate key kind — must be HMAC.
    let kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.key_id))?;
    let (hash_algo, tag_len) = match kind {
        HsmVaultKeyKind::_HmacSha256 => (HsmHashAlgo::Sha256, 32usize),
        HsmVaultKeyKind::_HmacSha384 => (HsmHashAlgo::Sha384, 48),
        HsmVaultKeyKind::_HmacSha512 => (HsmHashAlgo::Sha512, 64),
        _ => return Err(HsmError::InvalidKeyType),
    };

    // Validate sign permission.
    let attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if !attrs.sign() {
        return Err(HsmError::InvalidPermissions);
    }

    // Get key bytes and compute HMAC.
    let key_bytes = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;
    if tag_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    pal.hmac_sign(key_bytes, body.msg, &mut fmem[..tag_len])
        .await?;

    // Encode response.
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::Hmac,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiHmacResp {
        tag: &fmem[..tag_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

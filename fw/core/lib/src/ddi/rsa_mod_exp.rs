// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI RsaModExp command handler.
//!
//! Performs raw RSA private-key modular exponentiation (decrypt or
//! sign without padding). This is an in-session command.

use azihsm_fw_ddi_types::rsa_mod_exp::DdiRsaModExpReq;
use azihsm_fw_ddi_types::rsa_mod_exp::DdiRsaModExpResp;

use super::*;

/// Handle DdiRsaModExpCmd.
pub(crate) async fn rsa_mod_exp<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiRsaModExpReq<'_> = decoder.decode_data()?;

    let _sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Validate key kind — must be RSA private.
    let kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.key_id))?;
    match kind {
        HsmVaultKeyKind::Rsa2kPrivate
        | HsmVaultKeyKind::Rsa3kPrivate
        | HsmVaultKeyKind::Rsa4kPrivate
        | HsmVaultKeyKind::Rsa2kPrivateCrt
        | HsmVaultKeyKind::Rsa3kPrivateCrt
        | HsmVaultKeyKind::Rsa4kPrivateCrt => {}
        _ => return Err(HsmError::InvalidKeyType),
    }

    // Validate permissions based on op_type.
    let attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    match body.op_type {
        DdiRsaOpType::Decrypt => {
            if !attrs.decrypt() {
                return Err(HsmError::InvalidPermissions);
            }
        }
        DdiRsaOpType::Sign => {
            if !attrs.sign() {
                return Err(HsmError::InvalidPermissions);
            }
        }
        _ => return Err(HsmError::InvalidArg),
    }

    // Get key bytes and perform mod exp.
    // Input Y arrives in LE (host's y_pre_encode reversed BE→LE).
    // OpenSSL expects BE, so reverse before calling. Output X from
    // OpenSSL is BE; reverse to LE for the wire (host's x_post_decode
    // will reverse LE→BE).
    let key_der = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;
    let y_len = body.y.len();
    if y_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    // Reverse Y from LE to BE into fmem.
    for i in 0..y_len {
        fmem[i] = body.y[y_len - 1 - i];
    }
    // mod_exp_priv needs separate input/output; use a local buffer for
    // the BE input so fmem can hold the BE output.
    let y_be = fmem[..y_len].to_vec();
    pal.mod_exp_priv(key_der, &y_be, &mut fmem[..y_len]).await?;
    // Reverse output X from BE to LE.
    fmem[..y_len].reverse();

    // Encode response.
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::RsaModExp,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiRsaModExpResp { x: &fmem[..y_len] };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

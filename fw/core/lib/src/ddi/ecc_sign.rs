// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccSign command handler.
//!
//! Signs a pre-computed hash digest using an ECC private key stored in
//! the partition vault. Returns the ECDSA signature in PKA-native LE
//! format (`LE r || LE s`).
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::ecc_sign::DdiEccSignReq;
use azihsm_fw_ddi_types::ecc_sign::DdiEccSignResp;

use super::*;

/// Handle DdiEccSignCmd.
pub(crate) async fn ecc_sign<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiEccSignReq<'_> = decoder.decode_data()?;

    let _sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    if body.digest.is_empty() {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Validate key kind and permissions ──────────────────────────
    let kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.key_id))?;
    let sig_len = match kind {
        HsmVaultKeyKind::Ecc256Private => HsmEccCurve::P256.sig_len(),
        HsmVaultKeyKind::Ecc384Private => HsmEccCurve::P384.sig_len(),
        HsmVaultKeyKind::Ecc521Private => HsmEccCurve::P521.sig_len(),
        _ => return Err(HsmError::InvalidKeyType),
    };

    let attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if !attrs.sign() {
        return Err(HsmError::InvalidPermissions);
    }

    // ── 2. Get private key DER and sign ───────────────────────────────
    let priv_der = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;

    if sig_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    pal.ecc_sign(priv_der, body.digest, &mut fmem[..sig_len])
        .await?;

    // ── 3. Encode response ────────────────────────────────────────────
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::EccSign,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiEccSignResp {
        signature: &fmem[..sig_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

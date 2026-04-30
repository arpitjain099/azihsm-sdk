// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccSign command handler.
//!
//! Signs a pre-computed hash digest using an ECC private key stored in
//! the partition vault. Returns the ECDSA signature in PKA-native LE
//! format (`LE r || LE s`), padded to 4-byte-aligned component size
//! for P-521.
//!
//! The digest arrives from the host in PKA-native LE format (reversed
//! and zero-padded to 68 bytes by the host's `digest_pre_encode`).
//! The dispatcher reverses it back to BE before calling the PAL driver
//! (which uses OpenSSL internally).
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
    let pka_sig_len = match kind {
        HsmVaultKeyKind::Ecc256Private => HsmEccCurve::P256.pka_sig_len(),
        HsmVaultKeyKind::Ecc384Private => HsmEccCurve::P384.pka_sig_len(),
        HsmVaultKeyKind::Ecc521Private => HsmEccCurve::P521.pka_sig_len(),
        _ => return Err(HsmError::InvalidKeyType),
    };

    let attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if !attrs.sign() {
        return Err(HsmError::InvalidPermissions);
    }

    // ── 2. Get private key DER and sign ───────────────────────────────
    //       The digest arrives in LE from the wire (host's
    //       `digest_pre_encode` reversed BE→LE and padded to 68 bytes).
    //       The driver accepts LE directly (matches real PKA hardware).
    let priv_der = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;

    if pka_sig_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    pal.ecc_sign(priv_der, body.digest, &mut fmem[..pka_sig_len])
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
        signature: &fmem[..pka_sig_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

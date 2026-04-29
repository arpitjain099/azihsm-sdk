// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI AesEncryptDecrypt command handler.
//!
//! Performs AES-CBC encrypt or decrypt using a vault key identified by
//! `key_id`. This is an in-session command.

use azihsm_fw_ddi_types::aes_encrypt_decrypt::DdiAesEncryptDecryptReq;
use azihsm_fw_ddi_types::aes_encrypt_decrypt::DdiAesEncryptDecryptResp;

use super::*;

/// Handle DdiAesEncryptDecryptCmd.
pub(crate) async fn aes_encrypt_decrypt<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiAesEncryptDecryptReq<'_> = decoder.decode_data()?;

    let _sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    if body.msg.is_empty() {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Validate key kind ──────────────────────────────────────────
    let kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.key_id))?;
    match kind {
        HsmVaultKeyKind::Aes128 | HsmVaultKeyKind::Aes192 | HsmVaultKeyKind::Aes256 => {}
        _ => return Err(HsmError::InvalidKeyType),
    }

    // ── 2. Validate encrypt/decrypt permission ────────────────────────
    let attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    let encrypt = body.op == DdiAesOp::Encrypt;
    if encrypt && !attrs.encrypt() {
        return Err(HsmError::InvalidPermissions);
    }
    if !encrypt && !attrs.decrypt() {
        return Err(HsmError::InvalidPermissions);
    }

    // ── 3. Get raw key bytes ──────────────────────────────────────────
    let key_bytes = pal.vault_key(part_id, HsmKeyId::from(body.key_id))?;

    // ── 4. AES-CBC encrypt/decrypt ────────────────────────────────────
    let msg_len = body.msg.len();
    if msg_len % 16 != 0 {
        return Err(HsmError::InvalidArg);
    }
    if msg_len + 16 > fmem.len() {
        return Err(HsmError::InternalError);
    }

    // Copy IV into fmem scratch (mutable for chaining).
    let iv_off = msg_len;
    let mut iv_buf = [0u8; 16];
    if body.iv.len() == 16 {
        iv_buf.copy_from_slice(body.iv);
    }

    // Encrypt/decrypt into fmem[..msg_len].
    pal.aes_cbc_enc_dec(
        key_bytes,
        encrypt,
        &mut iv_buf,
        body.msg,
        &mut fmem[..msg_len],
    )
    .await?;

    // ── 5. Encode response ────────────────────────────────────────────
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::AesEncryptDecrypt,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiAesEncryptDecryptResp {
        msg: &fmem[..msg_len],
        iv: &iv_buf,
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

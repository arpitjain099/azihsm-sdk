// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetSessionEncryptionKey command handler.
//!
//! Returns the session-encryption public key, the partition nonce, and
//! a signature over the public key (signed with the partition identity
//! key). This is a NoSession command.
//!
//! Mirrors `GetEstablishCredEncryptionKey` but reads the session-enc
//! key instead of the establish-cred key.

use azihsm_fw_ddi_types::get_session_encryption_key::DdiGetSessionEncryptionKeyReq;
use azihsm_fw_ddi_types::get_session_encryption_key::DdiGetSessionEncryptionKeyResp;
use azihsm_fw_ddi_types::DdiPublicKeyFrameParams;

use super::*;

/// Handle DdiGetSessionEncryptionKeyCmd.
pub(crate) async fn get_session_encryption_key<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetSessionEncryptionKeyReq = decoder.decode_data()?;

    // Session encryption key must exist (partition must be enabled).
    let _se_kid = pal.part_session_enc_key_id(part_id)?;

    // Query sizes, then encode header + frame with reserved slots.
    let pub_key_len = pal.part_session_enc_pub_key(part_id, None)?;
    let nonce_len = pal.part_nonce(part_id, None)?;

    let mut encoder =
        ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::GetSessionEncryptionKey), smem)?;
    let frame = DdiGetSessionEncryptionKeyResp::frame(
        &mut encoder,
        DdiPublicKeyFrameParams {
            raw_len: pub_key_len,
            key_kind: DdiKeyType::Ecc384Public,
        },
        nonce_len,
        HsmEccCurve::P384.sig_len(),
    )?;
    let total = encoder.position();

    // Fill public key and nonce in-place.
    pal.part_session_enc_pub_key(part_id, Some(frame.pub_key.raw))?;
    pal.part_nonce(part_id, Some(frame.nonce))?;

    // Hash pub key, then sign directly into the signature slot.
    let id_priv_key = pal.vault_key(part_id, pal.part_id_key_id(part_id)?)?;

    let digest = &mut fmem[..HsmHashAlgo::Sha384.digest_len()];
    pal.hash(HsmHashAlgo::Sha384, frame.pub_key.raw, digest)
        .await?;
    pal.ecc_sign(id_priv_key, digest, frame.pub_key_signature)
        .await?;

    Ok(&smem[..total])
}

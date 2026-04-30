// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EcdhKeyExchange command handler.
//!
//! Derives a shared secret via ECDH using a vault-stored private key
//! and a peer's public key, stores the secret in the vault, masks it,
//! and returns the masked blob.
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::ecdh_key_exchange::DdiEcdhKeyExchangeReq;
use azihsm_fw_ddi_types::ecdh_key_exchange::DdiEcdhKeyExchangeResp;
use azihsm_fw_ddi_types::masked_key::*;

use super::*;
use crate::ddi::aes_generate_key::meta_bit;
use crate::ddi::aes_generate_key::BIT_DERIVE;
use crate::ddi::aes_generate_key::BIT_SESSION;
use crate::masked_key;

/// Maximum encoded length for the masked-key metadata MBOR blob.
const METADATA_BUF_LEN: usize = 128;

/// Handle DdiEcdhKeyExchangeCmd.
pub(crate) async fn ecdh_key_exchange<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiEcdhKeyExchangeReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let session_only = meta_bit(&body.key_properties.key_metadata.blob, BIT_SESSION);

    if session_only && body.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }
    if body.key_tag == Some(0) {
        return Err(HsmError::InvalidArg);
    }

    // ── 1. Validate private key: must be Ecc*Private with Derive ──────
    let priv_kind = pal.vault_key_kind(part_id, HsmKeyId::from(body.priv_key_id))?;
    let (secret_kind, secret_len) = match (priv_kind, body.key_type) {
        (HsmVaultKeyKind::Ecc256Private, DdiKeyType::Secret256) => {
            (HsmVaultKeyKind::Secret256, 32usize)
        }
        (HsmVaultKeyKind::Ecc384Private, DdiKeyType::Secret384) => (HsmVaultKeyKind::Secret384, 48),
        (HsmVaultKeyKind::Ecc521Private, DdiKeyType::Secret521) => (HsmVaultKeyKind::Secret521, 66),
        _ => return Err(HsmError::InvalidKeyType),
    };

    let priv_attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.priv_key_id))?;
    if !priv_attrs.derive() {
        return Err(HsmError::InvalidPermissions);
    }

    // ── 2. Validate output key usage ──────────────────────────────────
    if !meta_bit(&body.key_properties.key_metadata.blob, BIT_DERIVE) {
        return Err(HsmError::InvalidPermissions);
    }
    let mut attrs = HsmVaultKeyAttrs::new().with_derive(true).with_local(true);
    if session_only {
        attrs = attrs.with_session(true);
    }

    // ── 3. ECDH derive shared secret ──────────────────────────────────
    let priv_der = pal.vault_key(part_id, HsmKeyId::from(body.priv_key_id))?;
    if secret_len > fmem.len() {
        return Err(HsmError::InternalError);
    }
    // The peer pub key arrives as PKA-native raw LE (pre_encode
    // converted DER→raw LE for Physical devices).
    pal.ecdh_derive(priv_der, body.pub_key_der, &mut fmem[..secret_len])
        .await?;

    // ── 4. Store secret in vault ──────────────────────────────────────
    let session_id_for_vault = if session_only {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let guard = pal.vault_key_create(
        part_id,
        &fmem[..secret_len],
        secret_kind,
        session_id_for_vault,
        attrs,
        body.key_properties.key_metadata.blob.as_slice(),
    )?;
    let key_id = guard.dismiss();

    // ── 5. Mask the secret ────────────────────────────────────────────
    let masking_key = pal.session_masking_key(part_id, HsmSessId::from(sess_id))?;

    let sess_id_or_key_tag: u16 = if session_only {
        sess_id
    } else {
        body.key_tag.unwrap_or(0)
    };
    let mut metadata_buf = [0u8; METADATA_BUF_LEN];
    let metadata_len = encode_secret_metadata(
        &mut metadata_buf,
        body.key_type,
        &body.key_properties.key_metadata.blob,
        sess_id_or_key_tag,
        body.key_tag,
        secret_len as u16,
    )?;

    let padded_secret_len = secret_len.next_multiple_of(16);
    let bmk_len = masked_key::aes_cbc_envelope_len(metadata_len, padded_secret_len);
    let bmk_off = secret_len;
    if bmk_off + bmk_len > fmem.len() {
        return Err(HsmError::InternalError);
    }

    let mut pt_key = [0u8; 80]; // max secret: 66 for P-521, padded to 80
    pt_key[..secret_len].copy_from_slice(&fmem[..secret_len]);

    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &pt_key[..padded_secret_len],
        masking_key,
        &metadata_buf[..metadata_len],
        &mut fmem[bmk_off..bmk_off + bmk_len],
    )
    .await?;

    // ── 6. Encode response ────────────────────────────────────────────
    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::EcdhKeyExchange,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let resp_data = DdiEcdhKeyExchangeResp {
        key_id: u16::from(key_id),
        masked_key: &fmem[bmk_off..bmk_off + bmk_len],
    };
    let len = ddi::encode_resp(resp_hdr, resp_data, smem)?;
    Ok(&smem[..len])
}

/// MBOR-encode the masked-key metadata for a shared secret.
fn encode_secret_metadata(
    buf: &mut [u8; METADATA_BUF_LEN],
    key_type: DdiKeyType,
    target_meta: &[u8; 16],
    sess_id_or_key_tag: u16,
    key_tag: Option<u16>,
    key_length: u16,
) -> HsmResult<usize> {
    let mut attrs_blob = [0u8; 32];
    attrs_blob[..16].copy_from_slice(target_meta);
    attrs_blob[8..10].copy_from_slice(&sess_id_or_key_tag.to_le_bytes());

    let metadata = DdiMaskedKeyMetadata {
        svn: Some(1),
        key_type,
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

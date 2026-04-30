// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI DeleteKey command handler.
//!
//! Deletes a user-created key from the partition vault. Internal keys
//! (identity, establish-cred, session-enc, session) cannot be deleted.
//!
//! This is an in-session command.

use azihsm_fw_ddi_types::delete_key::DdiDeleteKeyReq;
use azihsm_fw_ddi_types::delete_key::DdiDeleteKeyResp;

use super::*;

/// Handle DdiDeleteKeyCmd.
pub(crate) fn delete_key<'a>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &impl HsmPal,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiDeleteKeyReq = decoder.decode_data()?;

    let _sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Reject deletion of internal keys.
    let attrs = pal.vault_key_attrs(part_id, HsmKeyId::from(body.key_id))?;
    if attrs.internal() {
        return Err(HsmError::InvalidPermissions);
    }

    pal.vault_key_delete(part_id, HsmKeyId::from(body.key_id))?;

    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::DeleteKey,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let len = ddi::encode_resp(resp_hdr, DdiDeleteKeyResp {}, smem)?;
    Ok(&smem[..len])
}

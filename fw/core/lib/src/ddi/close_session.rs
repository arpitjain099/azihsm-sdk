// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI CloseSession command handler.
//!
//! Tears down an existing session by deleting the session entry and its
//! associated vault keys via the PAL. This is a `SessionCtrl::Close`
//! command — `hdr.sess_id` must be present.

use azihsm_fw_ddi_types::close_session::DdiCloseSessionReq;
use azihsm_fw_ddi_types::close_session::DdiCloseSessionResp;

use super::*;

/// Handle DdiCloseSessionCmd.
pub(crate) fn close_session<'a>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &impl HsmPal,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiCloseSessionReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    pal.session_delete(part_id, HsmSessId::from(sess_id))?;

    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::CloseSession,
        sess_id: hdr.sess_id,
        status: 0,
        fips_approved: false,
    };
    let len = ddi::encode_resp(resp_hdr, DdiCloseSessionResp {}, smem)?;
    Ok(&smem[..len])
}

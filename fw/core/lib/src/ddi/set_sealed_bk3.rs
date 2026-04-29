// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI SetSealedBk3 command handler.
//!
//! Stores an opaque sealed-BK3 blob in per-partition storage. The blob
//! is then retrievable via [`GetSealedBk3`]. NoSession command.
//!
//! Single-shot: a partition's sealed-BK3 can only be set once. A second
//! `SetSealedBk3` returns [`HsmError::SealedBk3AlreadySet`]. The blob
//! survives `part_disable`/`part_enable` cycles and is cleared by
//! `part_free`.
//!
//! Reference implementations:
//! * `mcr-hsm/.../hsm/src/fsm/set_sealed_bk3.rs`
//! * `ddi/sim/src/dispatcher.rs::dispatch_set_sealed_bk3`
//!
//! [`GetSealedBk3`]: super::get_sealed_bk3

use azihsm_fw_ddi_types::set_sealed_bk3::DdiSetSealedBk3Req;
use azihsm_fw_ddi_types::set_sealed_bk3::DdiSetSealedBk3Resp;

use super::*;

/// Handle DdiSetSealedBk3Cmd.
pub(crate) fn set_sealed_bk3<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiSetSealedBk3Req = decoder.decode_data()?;

    pal.part_set_sealed_bk3(part_id, body.sealed_bk3)?;

    let len = ddi::encode_resp(
        ddi::success_hdr(hdr, DdiOp::SetSealedBk3),
        DdiSetSealedBk3Resp {},
        smem,
    )?;
    Ok(&smem[..len])
}

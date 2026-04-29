// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetSealedBk3 command handler.
//!
//! Returns the sealed-BK3 blob previously stored via [`SetSealedBk3`].
//! NoSession command. The blob is opaque to the firmware: the host
//! decides what to seal and how, up to the platform's per-partition
//! sealed-BK3 capacity.
//!
//! Reference implementations:
//! * `mcr-hsm/.../hsm/src/fsm/get_sealed_bk3.rs`
//! * `ddi/sim/src/dispatcher.rs::dispatch_get_sealed_bk3`
//!
//! Uses the encode-frame-then-fill pattern so the response data is
//! written directly into the encoder-reserved slot without an
//! intermediate copy.
//!
//! [`SetSealedBk3`]: super::set_sealed_bk3

use azihsm_fw_ddi_types::get_sealed_bk3::DdiGetSealedBk3Req;
use azihsm_fw_ddi_types::get_sealed_bk3::DdiGetSealedBk3Resp;

use super::*;

/// Handle DdiGetSealedBk3Cmd.
pub(crate) fn get_sealed_bk3<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetSealedBk3Req = decoder.decode_data()?;

    // Query size — surfaces SealedBk3NotPresent before we touch smem.
    let len = pal.part_sealed_bk3(part_id, None)?;

    // Encode header + frame, reserving space for the blob.
    let resp_hdr = ddi::success_hdr(hdr, DdiOp::GetSealedBk3);
    let mut encoder = ddi::encode_resp_hdr(&resp_hdr, smem)?;
    let frame = DdiGetSealedBk3Resp::frame(&mut encoder, len)?;
    let total = encoder.position();

    // Fill the reserved slice in-place.
    pal.part_sealed_bk3(part_id, Some(frame.sealed_bk3))?;

    Ok(&smem[..total])
}

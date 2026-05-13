// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI InitBk3 command handler.
//!
//! Initializes the partition BK3 flow end-to-end:
//! - generates BK_BOOT,
//! - returns BK3 masked under BK_BOOT,
//! - derives BKx from the firmware seed,
//! - stores BK_BOOT masked under BKx, and
//! - returns the VM launch GUID binding.

use azihsm_fw_core_crypto_bk_derive as bk_derive;
use azihsm_fw_core_crypto_key_mask as key_mask;
use azihsm_fw_ddi_mbor_types::init_bk3::DdiInitBk3Req;
use azihsm_fw_ddi_mbor_types::init_bk3::DdiInitBk3Resp;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::*;

const BK3_LABEL: &[u8] = b"BK3";
const BK_BOOT_LABEL: &[u8] = b"BKBoot";
const BK_BOOT_MK_LABEL: &[u8] = b"BK_BOOT_MK_DEFAULT";

/// Key attributes blob for BK3 and BK_BOOT masked-key metadata.
///
/// For these device-internal backup keys the attributes are all zeros
/// (no vault-level usage flags apply).
const KEY_ATTRIBUTES: [u8; 32] = [0u8; 32];

/// Handle DdiInitBk3Cmd.
pub(crate) async fn init_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiInitBk3Req<'_> = decoder.decode_data()?;

    match pal.part_masked_bk_boot(io, None) {
        Ok(_) => return Err(HsmError::Bk3AlreadyInitialized),
        Err(HsmError::KeyNotFound) => {}
        Err(err) => return Err(err),
    }
    let svn = pal.current_svn();
    let bks2_idx = pal.current_bks2_index();

    let bk3_md_params = key_mask::MetadataParams {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: &KEY_ATTRIBUTES,
        bks2_index: Some(bks2_idx),
        key_tag: None,
        label: BK3_LABEL,
        key_length: body.bk3.len() as u16,
    };
    let bk_boot_md_params = key_mask::MetadataParams {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: &KEY_ATTRIBUTES,
        bks2_index: Some(bks2_idx),
        key_tag: None,
        label: BK_BOOT_LABEL,
        key_length: bk_derive::MASKING_KEY_LEN as u16,
    };

    let bk3_metadata_len = key_mask::metadata_encoded_len(&bk3_md_params);
    let bk_boot_metadata_len = key_mask::metadata_encoded_len(&bk_boot_md_params);
    let masked_bk3_len = key_mask::cbc_envelope_len(bk3_metadata_len, body.bk3.len());
    let masked_bk_boot_len =
        key_mask::cbc_envelope_len(bk_boot_metadata_len, bk_derive::MASKING_KEY_LEN);

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::InitBk3), buf)?;
        let layout = DdiInitBk3Resp::reserve(&mut encoder, masked_bk3_len, VM_LAUNCH_GUID_SIZE)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiInitBk3Resp::from_layout(resp, &layout);

    pal.alloc_scoped_async(io, async |a| {
        let bk_boot = a.dma_alloc(bk_derive::MASKING_KEY_LEN)?;
        let bkx = a.dma_alloc(bk_derive::MASKING_KEY_LEN)?;
        let bk3_metadata = a.dma_alloc(bk3_metadata_len)?;
        let bk_boot_metadata = a.dma_alloc(bk_boot_metadata_len)?;
        let masked_bk_boot = a.dma_alloc(masked_bk_boot_len)?;

        let result: HsmResult<()> = async {
            bk_derive::bk_boot_key_gen(pal, io, &mut bk_boot[..], a).await?;

            let bk3_metadata_len =
                key_mask::encode_metadata(&mut bk3_metadata[..], &bk3_md_params)?;
            key_mask::mask_cbc(
                pal,
                io,
                body.bk3,
                &bk_boot[..],
                &bk3_metadata[..bk3_metadata_len],
                frame.masked_bk3,
                a,
            )
            .await?;

            pal.derive_masking_key(
                io,
                pal.fw_seed(),
                BK_BOOT_MK_LABEL,
                &[],
                svn,
                bks2_idx,
                &mut bkx[..],
            )
            .await?;

            let bk_boot_metadata_len =
                key_mask::encode_metadata(&mut bk_boot_metadata[..], &bk_boot_md_params)?;
            key_mask::mask_cbc(
                pal,
                io,
                &bk_boot[..],
                &bkx[..],
                &bk_boot_metadata[..bk_boot_metadata_len],
                &mut masked_bk_boot[..],
                a,
            )
            .await?;

            pal.part_set_masked_bk_boot(io, &masked_bk_boot[..])?;
            pal.part_vm_launch_guid(io, Some(frame.vm_launch_guid))?;

            Ok(())
        }
        .await;

        bk_boot.fill(0);
        bkx.fill(0);
        bk3_metadata.fill(0);
        bk_boot_metadata.fill(0);
        masked_bk_boot.fill(0);

        result
    })
    .await?;

    Ok(resp)
}

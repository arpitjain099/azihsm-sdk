// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI InitBk3 command handler.
//!
//! Single-shot per-partition operation that:
//!
//! 1. Generates a fresh per-partition BK_BOOT key
//!    (`KBKDF-SHA384(random_seed, "BK_BOOT_KEY_DEFAULT", 80)`).
//! 2. Masks the host-supplied 48-byte BK3 with that BK_BOOT into a
//!    [`MaskedKey`](crate::masked_key) AES-CBC-256 + HMAC-SHA-384
//!    envelope, returned to the host as `masked_bk3`.
//! 3. Derives the firmware-wide BK_BOOT_MASKING_KEY
//!    (`KBKDF-SHA384(DEVICE_ROOT_KEY, "BK_BOOT_MK_DEFAULT", BKS1‖BKS2,
//!    80)`).
//! 4. Masks BK_BOOT itself with BK_BOOT_MASKING_KEY into a second
//!    MaskedKey envelope, stored in partition state for use by
//!    `EstablishCredential`.
//! 5. Returns a 16-byte `vm_launch_guid` (currently zeros — matches the
//!    sim's TODO).
//!
//! Mirrors `mcr-hsm/.../hsm/src/fsm/init_bk3.rs`. NoSession command.
//!
//! Errors:
//! * [`HsmError::Bk3AlreadyInitialized`] — `InitBk3` already ran for
//!   this partition.

use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_types::init_bk3::DdiInitBk3Req;
use azihsm_fw_ddi_types::init_bk3::DdiInitBk3Resp;
use azihsm_fw_ddi_types::masked_key::DdiMaskedKeyAttributes;
use azihsm_fw_ddi_types::masked_key::DdiMaskedKeyMetadata;

use super::*;
use crate::lm_key_derive;
use crate::masked_key;

/// Length in bytes of a BK3 plaintext.
const BK3_LEN: usize = 48;

/// Length in bytes of a BK_BOOT key (= AES-256 key + HMAC-SHA-384 key).
const BK_BOOT_LEN: usize = 80;

/// Length in bytes of the partition's VM launch GUID. Currently zeros
/// for the simulator (matches `ddi/sim` TODO).
const VM_LAUNCH_GUID_LEN: usize = 16;

/// Maximum bytes a single MBOR-encoded `DdiMaskedKeyMetadata` should
/// take. The encoded BK3 / BK_BOOT metadata is well under 96 bytes;
/// 128 leaves slack and matches mcr-hsm's `METADATA_MAX_SIZE_BYTES`.
const METADATA_MAX_SIZE_BYTES: usize = 128;

/// Stack-allocated zero buffer used as the "attributes" blob in
/// metadata. The codec treats it as opaque; both sim and mcr-hsm pass
/// 32 zero bytes for BK3 / BK_BOOT.
const ATTR_ZERO_BLOB: [u8; 32] = [0u8; 32];

/// Handle DdiInitBk3Cmd.
pub(crate) async fn init_bk3<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiInitBk3Req = decoder.decode_data()?;

    // Validate BK3 length (must be exactly 48 bytes).
    if body.bk3.len() != BK3_LEN {
        return Err(HsmError::InvalidArg);
    }

    // Reject if InitBk3 already ran for this partition.
    if pal.part_masked_bk_boot(part_id, None).is_ok() {
        return Err(HsmError::Bk3AlreadyInitialized);
    }

    // ── 1. Encode the BK3 metadata into the start of fmem ─────────
    let bk3_metadata_len =
        encode_metadata(&mut fmem[..METADATA_MAX_SIZE_BYTES], b"BK3", BK3_LEN as u16)?;

    // ── 2. Encode the BK_BOOT metadata into the next slot of fmem ──
    let bk_boot_metadata_off = METADATA_MAX_SIZE_BYTES;
    let bk_boot_metadata_len = encode_metadata(
        &mut fmem[bk_boot_metadata_off..bk_boot_metadata_off + METADATA_MAX_SIZE_BYTES],
        b"BK_BOOT",
        BK_BOOT_LEN as u16,
    )?;

    // ── 3. Compute envelope sizes ──────────────────────────────────
    let masked_bk3_len = masked_key::aes_cbc_envelope_len(bk3_metadata_len, BK3_LEN);
    let masked_bk_boot_len = masked_key::aes_cbc_envelope_len(bk_boot_metadata_len, BK_BOOT_LEN);

    // ── 4. Encode the response header + frame in smem (this also
    //         carves out the masked_bk3 destination slot) ──────────
    let resp_hdr = ddi::success_hdr(hdr, DdiOp::InitBk3);
    let mut encoder = ddi::encode_resp_hdr(&resp_hdr, smem)?;
    let frame = DdiInitBk3Resp::frame(&mut encoder, masked_bk3_len, VM_LAUNCH_GUID_LEN)?;
    let total = encoder.position();

    // Copy bk3 to a stack-local because `body.bk3` borrows from the
    // decoder and we need to release that borrow before calling the
    // PAL crypto methods (which await).
    let mut bk3_local = [0u8; BK3_LEN];
    bk3_local.copy_from_slice(body.bk3);

    // Copy the metadata bytes out of fmem — the masked_bk_boot
    // encoding step below needs both metadata slices and a scratch
    // region; cleaner to stage them on the stack.
    let mut bk3_md_local = [0u8; METADATA_MAX_SIZE_BYTES];
    bk3_md_local[..bk3_metadata_len].copy_from_slice(&fmem[..bk3_metadata_len]);
    let mut bk_boot_md_local = [0u8; METADATA_MAX_SIZE_BYTES];
    bk_boot_md_local[..bk_boot_metadata_len]
        .copy_from_slice(&fmem[bk_boot_metadata_off..bk_boot_metadata_off + bk_boot_metadata_len]);

    // ── 5. Generate fresh per-partition BK_BOOT ────────────────────
    let mut bk_boot = [0u8; BK_BOOT_LEN];
    lm_key_derive::bk_boot_key_gen(pal, &mut bk_boot).await?;

    // ── 6. Mask BK3 with BK_BOOT into the response slot ────────────
    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &bk3_local,
        &bk_boot,
        &bk3_md_local[..bk3_metadata_len],
        frame.masked_bk3,
    )
    .await?;

    // ── 7. Derive BK_BOOT_MASKING_KEY ─────────────────────────────
    let mut bbmk = [0u8; BK_BOOT_LEN];
    lm_key_derive::bk_boot_masking_key(pal, &mut bbmk).await?;

    // ── 8. Mask BK_BOOT with BK_BOOT_MASKING_KEY into fmem scratch ─
    //         and store the result in partition state ─────────────────
    let masked_bk_boot_off = 2 * METADATA_MAX_SIZE_BYTES;
    if fmem.len() < masked_bk_boot_off + masked_bk_boot_len {
        return Err(HsmError::DdiEncodeFailed);
    }
    masked_key::encode_aes_cbc_256_hmac384(
        pal,
        &bk_boot,
        &bbmk,
        &bk_boot_md_local[..bk_boot_metadata_len],
        &mut fmem[masked_bk_boot_off..masked_bk_boot_off + masked_bk_boot_len],
    )
    .await?;
    pal.part_set_masked_bk_boot(
        part_id,
        &fmem[masked_bk_boot_off..masked_bk_boot_off + masked_bk_boot_len],
    )?;

    // ── 9. Fill VM launch GUID (zeros for the simulator) ───────────
    frame.vm_launch_guid.fill(0);

    // Wipe sensitive scratch on the way out.
    bk3_local.fill(0);
    bk_boot.fill(0);
    bbmk.fill(0);

    Ok(&smem[..total])
}

/// MBOR-encode a [`DdiMaskedKeyMetadata`] into `out` and return the
/// length actually written. Uses the static field values shared by the
/// BK3 and BK_BOOT cases; only `key_label` and `key_length` differ.
fn encode_metadata(out: &mut [u8], label: &[u8], key_length: u16) -> HsmResult<usize> {
    use azihsm_fw_ddi_mbor::MborEncode;

    let metadata = DdiMaskedKeyMetadata {
        svn: Some(0),
        key_type: DdiKeyType::Secret384,
        key_attributes: DdiMaskedKeyAttributes {
            blob: &ATTR_ZERO_BLOB,
        },
        bks2_index: None,
        key_tag: None,
        key_label: label,
        key_length,
    };

    let mut enc = MborEncoder::new(out);
    metadata.mbor_encode(&mut enc)?;
    Ok(enc.position())
}

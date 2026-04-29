// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Live Migration key derivation primitives.
//!
//! Mirrors the production firmware (mcr-hsm) `LMKeyDerive` module
//! (`hsm/src/lm_key_derive/key_derive.rs`) for the operations the
//! current fw stack actually performs:
//!
//! * [`bk_boot_key_gen`] — generate a per-partition BK_BOOT key.
//!   `KBKDF-SHA384(random_seed, "BK_BOOT_KEY_DEFAULT", length=80)`.
//! * [`bk_boot_masking_key`] — derive the firmware-wide BK_BOOT
//!   masking key. `KBKDF-SHA384(DEVICE_ROOT_KEY, "BK_BOOT_MK_DEFAULT",
//!   BKS1‖BKS2, length=80)`.
//!
//! # Constants
//!
//! [`BKS1`] and [`BKS2`] are firmware-wide seeds used as the KBKDF
//! context. Their byte values mirror `ddi/sim/src/function.rs:67-79`
//! exactly so cross-tool key derivation lines up.
//!
//! [`DEVICE_ROOT_KEY`] is the only true hardcode in the chain. In
//! production fw it would be injected at provisioning time (for
//! mcr-hsm: read out of fused silicon). For the Std PAL simulator, a
//! fixed compile-time constant stands in for the hardware-rooted
//! secret. **Do not use this code path for any production workload.**

use azihsm_fw_hsm_pal_traits::*;

/// Size in bytes of the AES-256-CBC + HMAC-SHA-384 composite key used
/// for masking BK3 and BK_BOOT.
///
/// Layout: 32 bytes AES-256 key followed by 48 bytes HMAC-SHA-384 key.
pub const BK_AES_CBC_256_HMAC384_SIZE_BYTES: usize = 32 + 48;

/// Size in bytes of the random seed fed into [`bk_boot_key_gen`].
///
/// 48 bytes matches mcr-hsm's `MK_SEED_SIZE_BYTES`.
pub const BK_BOOT_KEY_SEED_SIZE_BYTES: usize = 48;

/// Size in bytes of one BKS seed (BKS1 / BKS2).
pub const BK_SEED_SIZE_BYTES: usize = 32;

/// Size in bytes of the firmware-wide root secret (a.k.a. `FW_SECRET`
/// in mcr-hsm).
pub const FW_SECRET_SIZE_BYTES: usize = 48;

/// KBKDF label for [`bk_boot_key_gen`]. Mirrors mcr-hsm
/// `BK_BOOT_DEFAULT_LABEL` byte-for-byte.
pub const BK_BOOT_KEY_DEFAULT_LABEL: &[u8] = b"BK_BOOT_KEY_DEFAULT";

/// KBKDF label for [`bk_boot_masking_key`]. Mirrors mcr-hsm
/// `BK_BOOT_MASKING_KEY_DEFAULT_LABEL` byte-for-byte.
pub const BK_BOOT_MASKING_KEY_DEFAULT_LABEL: &[u8] = b"BK_BOOT_MK_DEFAULT";

/// Backup seed 1. Firmware-wide constant. Bytes mirror
/// `ddi/sim/src/function.rs:67`.
pub const BKS1: [u8; BK_SEED_SIZE_BYTES] = [
    0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb, 0x68, 0xeb, 0x26, 0x99,
    0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c, 0x21, 0x02, 0xb0, 0xac,
];

/// Backup seed 2. Firmware-wide constant. Bytes mirror
/// `ddi/sim/src/function.rs:73`.
pub const BKS2: [u8; BK_SEED_SIZE_BYTES] = [
    0xad, 0x1a, 0x17, 0xe9, 0xed, 0x38, 0x27, 0x5e, 0x8b, 0x30, 0x5d, 0xb8, 0x19, 0x0f, 0x82, 0xb6,
    0x2d, 0xa2, 0x5a, 0xc6, 0xf0, 0x70, 0xa3, 0xe1, 0x75, 0x9c, 0x61, 0x92, 0xcc, 0xf4, 0x19, 0xa3,
];

/// Simulator stand-in for the hardware-rooted firmware secret used as
/// the input key to [`bk_boot_masking_key`].
///
/// In production fw this would be injected at provisioning (mcr-hsm
/// reads it from fuses); the value is opaque to anything outside this
/// firmware build. For the Std PAL emulator we hardcode 48 bytes that
/// are clearly distinct from BKS1/BKS2/BK_BOOT and have no security
/// meaning.
const DEVICE_ROOT_KEY: [u8; FW_SECRET_SIZE_BYTES] = [
    // "AZIHSM_EMU_DEVICE_ROOT_v1\0\0\0\0\0\0\0" with the rest zero-filled.
    0x41, 0x5a, 0x49, 0x48, 0x53, 0x4d, 0x5f, 0x45, 0x4d, 0x55, 0x5f, 0x44, 0x45, 0x56, 0x49, 0x43,
    0x45, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Generate a fresh per-partition BK_BOOT composite key.
///
/// Mirrors mcr-hsm `LMKeyDerive::bk_boot_key_gen`: a fresh random seed
/// is fed into `KBKDF-SHA384` with label
/// [`BK_BOOT_KEY_DEFAULT_LABEL`] and no context. The 80-byte output
/// is the AES‖HMAC composite usable directly as a masking key.
///
/// `bk_boot_key_out.len()` must equal
/// [`BK_AES_CBC_256_HMAC384_SIZE_BYTES`] (80).
pub async fn bk_boot_key_gen<P: HsmPal>(pal: &P, bk_boot_key_out: &mut [u8]) -> HsmResult<()> {
    if bk_boot_key_out.len() != BK_AES_CBC_256_HMAC384_SIZE_BYTES {
        return Err(HsmError::InvalidArg);
    }

    let mut seed = [0u8; BK_BOOT_KEY_SEED_SIZE_BYTES];
    pal.rng_fill_bytes(&mut seed)?;

    pal.kbkdf(
        &seed,
        HsmHashAlgo::Sha384,
        BK_BOOT_KEY_DEFAULT_LABEL,
        &[],
        bk_boot_key_out,
    )
    .await
}

/// Derive the firmware-wide BK_BOOT masking key.
///
/// Mirrors mcr-hsm `LMKeyDerive::generate_bkx`:
/// `KBKDF-SHA384(DEVICE_ROOT_KEY, "BK_BOOT_MK_DEFAULT", BKS1‖BKS2, 80)`.
/// Deterministic — same output every call.
///
/// `out.len()` must equal [`BK_AES_CBC_256_HMAC384_SIZE_BYTES`].
pub async fn bk_boot_masking_key<P: HsmPal>(pal: &P, out: &mut [u8]) -> HsmResult<()> {
    if out.len() != BK_AES_CBC_256_HMAC384_SIZE_BYTES {
        return Err(HsmError::InvalidArg);
    }

    let mut bks1_2 = [0u8; BK_SEED_SIZE_BYTES * 2];
    bks1_2[..BK_SEED_SIZE_BYTES].copy_from_slice(&BKS1);
    bks1_2[BK_SEED_SIZE_BYTES..].copy_from_slice(&BKS2);

    pal.kbkdf(
        &DEVICE_ROOT_KEY,
        HsmHashAlgo::Sha384,
        BK_BOOT_MASKING_KEY_DEFAULT_LABEL,
        &bks1_2,
        out,
    )
    .await
}

/// Split an 80-byte AES‖HMAC composite into its two halves.
///
/// Returns `(aes_key (32B), hmac_key (48B))`. Returns
/// [`HsmError::InvalidArg`] if `key` is not exactly 80 bytes long.
pub fn split_aes_hmac_key(key: &[u8]) -> HsmResult<(&[u8], &[u8])> {
    if key.len() != BK_AES_CBC_256_HMAC384_SIZE_BYTES {
        return Err(HsmError::InvalidArg);
    }
    Ok(key.split_at(32))
}

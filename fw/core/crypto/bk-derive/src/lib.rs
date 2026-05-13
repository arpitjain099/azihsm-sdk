// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! Live Migration key derivation primitives.
//!
//! Firmware-side equivalent of the production `LMKeyDerive` module.
//! All operations that need crypto go through the PAL trait surface
//! (`HsmKdf`, `HsmRng`) and use `HsmScopedAlloc` for DMA scratch.
//!
//! ## Naming conventions
//!
//! | Function | Production equivalent | Purpose |
//! |---|---|---|
//! | [`bk_boot_key_gen`] | `bk_boot_key_gen` | Generate random BK_BOOT (80B) |
//! | [`bk3_session_gen`] | `bk3_session_gen` | Derive per-session BK3 from partition BK3 |
//! | [`generate_mk`] | `generate_mk` | Generate random masking key (80B) |
//!
//! ## Memory model
//!
//! All public functions that call `sp800_108_kdf` or `rng_fill_bytes`
//! take `alloc: &'a impl HsmScopedAlloc` so callers control the DMA
//! scratch lifetime. No `unsafe DmaBuf::from_raw`.

use azihsm_fw_hsm_pal_traits::*;

// ── Constants ─────────────────────────────────────────────────────────

/// AES-CBC-256 key size in bytes.
pub const AES_KEY_LEN: usize = 32;

/// HMAC-SHA-384 key/tag size in bytes.
pub const HMAC_KEY_LEN: usize = 48;

/// Size of the AES-CBC-256 + HMAC-SHA-384 composite masking key.
///
/// Layout: `AES-256 key (32B) || HMAC-SHA-384 key (48B)`.
pub const MASKING_KEY_LEN: usize = AES_KEY_LEN + HMAC_KEY_LEN; // 80

/// BK3 plaintext size in bytes.
pub const BK3_LEN: usize = 48;

/// Random seed size for KBKDF-based key generation.
const SEED_LEN: usize = 48;

// ── KBKDF labels (must match production exactly) ──────────────────────

/// KBKDF label for [`bk_boot_key_gen`].
const BK_BOOT_KEY_LABEL: &[u8] = b"BK_BOOT_KEY_DEFAULT";

/// KBKDF label for [`bk3_session_gen`].
const SESSION_BK3_LABEL: &[u8] = b"SESSION_BK3";

/// KBKDF label for [`generate_mk`].
const MK_DEFAULT_LABEL: &[u8] = b"MK_DEFAULT";

// ── Helpers ───────────────────────────────────────────────────────────

/// Copy `src` into a freshly allocated DMA buffer.
fn dma_copy_in<'a>(alloc: &'a impl HsmScopedAlloc, src: &[u8]) -> HsmResult<&'a mut DmaBuf> {
    let buf = alloc.dma_alloc(src.len())?;
    buf.copy_from_slice(src);
    Ok(buf)
}

/// Run `sp800_108_kdf` with the given key, label, context, and output
/// length, using `alloc` for all DMA scratch.
async fn kbkdf_sha384<'a, P: HsmKdf>(
    pal: &P,
    io: &impl HsmIo,
    key: &[u8],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()> {
    let key_dma = dma_copy_in(alloc, key)?;
    let label_dma = dma_copy_in(alloc, label)?;
    let ctx_dma = dma_copy_in(alloc, context)?;
    let out_dma = alloc.dma_alloc(output.len())?;

    pal.sp800_108_kdf(
        io,
        HsmHashAlgo::Sha384,
        key_dma,
        label_dma,
        ctx_dma,
        out_dma,
    )
    .await?;

    output.copy_from_slice(out_dma);

    // Wipe sensitive scratch.
    key_dma.fill(0);
    out_dma.fill(0);

    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────

/// Generate a fresh per-partition BK_BOOT composite key.
///
/// `KBKDF-SHA384(random_seed, "BK_BOOT_KEY_DEFAULT", no_context, 80)`.
///
/// # Parameters
///
/// - `pal` -- PAL providing RNG and KBKDF.
/// - `io` -- caller's I/O context.
/// - `bk_boot_out` -- destination buffer; must be exactly
///   [`MASKING_KEY_LEN`] (80) bytes.
/// - `alloc` -- scoped allocator for DMA scratch.
pub async fn bk_boot_key_gen<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    bk_boot_out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmKdf + HsmRng + 'a,
{
    if bk_boot_out.len() != MASKING_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }

    // Generate random seed.
    let seed = alloc.dma_alloc(SEED_LEN)?;
    pal.rng_fill_bytes(io, seed)?;

    // Derive BK_BOOT via KBKDF.
    kbkdf_sha384(pal, io, seed, BK_BOOT_KEY_LABEL, &[], bk_boot_out, alloc).await?;

    // Wipe seed.
    seed.fill(0);

    Ok(())
}

pub async fn bk3_session_gen<'a, P: HsmKdf + 'a>(
    pal: &P,
    io: &impl HsmIo,
    bk3_partition: &[u8],
    bk3_session_out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()> {
    if bk3_partition.len() != BK3_LEN || bk3_session_out.len() != BK3_LEN {
        return Err(HsmError::InvalidArg);
    }

    kbkdf_sha384(
        pal,
        io,
        bk3_partition,
        SESSION_BK3_LABEL,
        &[],
        bk3_session_out,
        alloc,
    )
    .await
}

pub async fn generate_mk<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    mk_out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmKdf + HsmRng + 'a,
{
    if mk_out.len() != MASKING_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }

    let seed = alloc.dma_alloc(SEED_LEN)?;
    pal.rng_fill_bytes(io, seed)?;

    kbkdf_sha384(pal, io, seed, MK_DEFAULT_LABEL, &[], mk_out, alloc).await?;

    seed.fill(0);

    Ok(())
}

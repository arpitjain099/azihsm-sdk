// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! MaskedKey envelope codec — AES-CBC-256 + HMAC-SHA-384.
//!
//! Implements the same wire format used by the mcr-hsm host SDK
//! (`azihsm_ddi_types::MaskedKey`) and the sim
//! (`ddi/sim/src/masked_key`), but targeting the firmware PAL crypto
//! trait surface (`HsmAes`, `HsmHmac`, `HsmRng`, `HsmScopedAlloc`).
//!
//! # Wire format (AES-CBC-256 + HMAC-SHA-384)
//!
//! All `u16` fields are native-endian (LE on the target).
//!
//! ```text
//! Offset  Size   Field
//! ──────  ────   ──────────────────────────────────
//!      0     2   version (u16)          ─┐
//!      2     2   algorithm (u16)         │ MaskedKeyHeader
//!                                       ─┘
//!      4     2   iv_len (u16)           ─┐
//!      6     2   post_iv_pad_len (u16)   │
//!      8     2   metadata_len (u16)      │
//!     10     2   post_metadata_pad_len   │ AesHeader
//!     12     2   encrypted_key_len       │
//!     14     2   post_enc_key_pad_len    │
//!     16     2   tag_len (u16)           │
//!     18    34   reserved (zeros)       ─┘
//!     52    16   IV
//!     68     p   post-IV padding (zeros, p = next_mul4(iv_len) - iv_len)
//!   68+p     m   metadata (MBOR-encoded DdiMaskedKeyMetadata)
//! 68+p+m    pm   post-metadata padding (zeros, pm = next_mul4(m) - m)
//!    ...     e   encrypted_key (AES-CBC-256, zero-padded to block boundary)
//!    ...    pe   post-encrypted-key padding (zeros)
//!    ...    48   HMAC-SHA-384 tag
//! ```
//!
//! The HMAC tag covers everything from offset 0 up to (but not
//! including) the tag itself.
//!
//! # Padding
//!
//! The plaintext key is **zero-padded** to the next 16-byte boundary
//! before AES-CBC encryption (matching the sim's
//! `aescbc256_enc_data_len`). This is NOT PKCS#7 padding — the actual
//! key length is recorded in the metadata's `key_length` field, and
//! the decoder uses that to strip the trailing zeros.
//!
//! # Memory model
//!
//! All public functions take `alloc: &'a impl HsmScopedAlloc` and
//! route intermediate crypto buffers (AES key, IV, ciphertext,
//! HMAC key, tag) through scoped DMA allocations. No
//! `unsafe DmaBuf::from_raw` — every DMA buffer is properly
//! allocated. Sensitive scratch is explicitly zeroed before the
//! scoped allocator reclaims it.
//!
//! # Metadata helpers
//!
//! [`build_metadata`], [`metadata_encoded_len`], and
//! [`encode_metadata`] construct the [`DdiMaskedKeyMetadata`] blob
//! that goes into the envelope's metadata region. Centralised here
//! so every caller of [`mask_cbc`] uses the same conventions.

use core::mem::size_of;

use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborLen;
use azihsm_fw_ddi_mbor::MborLenAccumulator;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyAttributes;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::*;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

// ── Constants ─────────────────────────────────────────────────────────

const AES_BLOCK: usize = 16;
const IV_LEN: usize = 16;
const HMAC_TAG_LEN: usize = 48;
const AES_KEY_LEN: usize = 32;
const FORMAT_V1: u16 = 1;
const ALGO_AES_CBC_256_HMAC_384: u16 = 1;
const MASKING_KEY_LEN: usize = AES_KEY_LEN + HMAC_TAG_LEN; // 80

// ── Wire-format header ────────────────────────────────────────────────

/// Fixed header at the start of every MaskedKey envelope.
///
/// 4 bytes: version (u16) + algorithm (u16).
/// Mirrors `azihsm_ddi_types::MaskedKeyHeader`.
#[repr(C)]
#[derive(Clone, Copy, Debug, IntoBytes, KnownLayout, TryFromBytes, Immutable)]
struct Header {
    version: u16,
    algorithm: u16,
}

/// AES-specific sub-header following `Header`.
///
/// 48 bytes of length fields + 34 bytes reserved = 48 + 34 = 82?
/// Actually: 7 × u16 = 14 bytes + 34 reserved = 48 bytes total.
/// Mirrors `azihsm_ddi_types::MaskedKeyAesHeader`.
#[repr(C)]
#[derive(Clone, Copy, Debug, IntoBytes, KnownLayout, TryFromBytes, Immutable)]
struct AesSubHeader {
    iv_len: u16,
    post_iv_pad_len: u16,
    metadata_len: u16,
    post_metadata_pad_len: u16,
    encrypted_key_len: u16,
    post_encrypted_key_pad_len: u16,
    tag_len: u16,
    reserved: [u8; 34],
}

/// Combined header size (Header + AesSubHeader).
const FULL_HEADER_LEN: usize = size_of::<Header>() + size_of::<AesSubHeader>();

// Compile-time assertions matching the host-side static_asserts.
const _: () = assert!(size_of::<Header>() == 4);
const _: () = assert!(size_of::<AesSubHeader>() == 48);
const _: () = assert!(FULL_HEADER_LEN == 52);

// ── Layout computation ────────────────────────────────────────────────

/// Pre-computed offsets and lengths for a MaskedKey envelope.
struct Layout {
    // Field lengths.
    post_iv_pad: usize,
    metadata_len: usize,
    post_metadata_pad: usize,
    encrypted_key_len: usize,
    post_encrypted_key_pad: usize,
    // Derived offsets (relative to buffer start).
    iv_off: usize,
    metadata_off: usize,
    encrypted_key_off: usize,
    tag_off: usize,
    total_len: usize,
}

impl Layout {
    fn compute(metadata_len: usize, plaintext_key_len: usize) -> Self {
        let post_iv_pad = next_pad4(IV_LEN);
        let post_metadata_pad = next_pad4(metadata_len);
        // Zero-pad to the next 16-byte boundary (matches sim's aescbc256_enc_data_len).
        let encrypted_key_len = plaintext_key_len.div_ceil(AES_BLOCK) * AES_BLOCK;
        let post_encrypted_key_pad = next_pad4(encrypted_key_len);

        let iv_off = FULL_HEADER_LEN;
        let metadata_off = iv_off + IV_LEN + post_iv_pad;
        let encrypted_key_off = metadata_off + metadata_len + post_metadata_pad;
        let tag_off = encrypted_key_off + encrypted_key_len + post_encrypted_key_pad;
        let total_len = tag_off + HMAC_TAG_LEN;

        Self {
            post_iv_pad,
            metadata_len,
            post_metadata_pad,
            encrypted_key_len,
            post_encrypted_key_pad,
            iv_off,
            metadata_off,
            encrypted_key_off,
            tag_off,
            total_len,
        }
    }
}

/// Padding needed to reach the next 4-byte boundary.
#[inline]
fn next_pad4(len: usize) -> usize {
    len.next_multiple_of(4) - len
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Allocate a DMA buffer and copy `src` into it.
fn dma_copy_in<'a>(alloc: &'a impl HsmScopedAlloc, src: &[u8]) -> HsmResult<&'a mut DmaBuf> {
    let buf = alloc.dma_alloc(src.len())?;
    buf.copy_from_slice(src);
    Ok(buf)
}

/// Split an 80-byte AES‖HMAC composite masking key.
/// Split an 80-byte AES‖HMAC composite masking key into its two
/// halves.
///
/// Returns `(aes_key (32B), hmac_key (48B))`.
pub fn split_masking_key(key: &[u8]) -> HsmResult<(&[u8], &[u8])> {
    if key.len() != MASKING_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(key.split_at(AES_KEY_LEN))
}

// ── Public API: envelope sizing ───────────────────────────────────────

/// Compute the total encoded length of an AES-CBC-256 + HMAC-SHA-384
/// MaskedKey envelope.
///
/// `metadata_len` is the MBOR-encoded length of the metadata blob
/// (obtainable via [`metadata_encoded_len`]). `plaintext_key_len` is
/// the raw key length before zero-padding to the AES block boundary.
pub fn cbc_envelope_len(metadata_len: usize, plaintext_key_len: usize) -> usize {
    Layout::compute(metadata_len, plaintext_key_len).total_len
}

// ── Public API: mask ──────────────────────────────────────────────────

/// Mask a key into an AES-CBC-256 + HMAC-SHA-384 envelope.
///
/// # Parameters
///
/// - `pal` — PAL providing AES-CBC, HMAC-SHA-384, and RNG.
/// - `io` — caller's I/O context (per-IO scope).
/// - `plaintext_key` — the key bytes to encrypt. Zero-padded to the
///   next 16-byte boundary before encryption (the actual key length
///   is recorded in the metadata's `key_length` field).
/// - `masking_key` — 80-byte AES(32) ‖ HMAC(48) composite key.
/// - `metadata_bytes` — pre-MBOR-encoded metadata to embed
///   (integrity-protected, not encrypted). Use [`encode_metadata`]
///   to produce this.
/// - `out` — destination buffer; must be exactly
///   [`cbc_envelope_len`]`(metadata_bytes.len(), plaintext_key.len())`
///   bytes. On success, contains the complete envelope.
/// - `alloc` — scoped allocator owning every intermediate DMA
///   buffer. Caller sets up the scope via
///   `HsmAlloc::alloc_scoped_async`.
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] — `plaintext_key` is empty, `out` is
///   the wrong size, or `masking_key` is not 80 bytes.
/// - [`HsmError::NotEnoughSpace`] — scoped allocator exhausted.
/// - Propagated from AES / HMAC / RNG PAL methods.
pub async fn mask_cbc<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    plaintext_key: &[u8],
    masking_key: &[u8],
    metadata_bytes: &[u8],
    out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmAes + HsmHmac + HsmRng + 'a,
{
    if plaintext_key.is_empty() {
        return Err(HsmError::InvalidArg);
    }

    let layout = Layout::compute(metadata_bytes.len(), plaintext_key.len());
    if out.len() != layout.total_len {
        return Err(HsmError::InvalidArg);
    }

    let (aes_key, hmac_key) = split_masking_key(masking_key)?;

    // ── 1. Write headers ──────────────────────────────────────────

    let header = Header {
        version: FORMAT_V1,
        algorithm: ALGO_AES_CBC_256_HMAC_384,
    };
    out[..size_of::<Header>()].copy_from_slice(header.as_bytes());

    let sub = AesSubHeader {
        iv_len: IV_LEN as u16,
        post_iv_pad_len: layout.post_iv_pad as u16,
        metadata_len: layout.metadata_len as u16,
        post_metadata_pad_len: layout.post_metadata_pad as u16,
        encrypted_key_len: layout.encrypted_key_len as u16,
        post_encrypted_key_pad_len: layout.post_encrypted_key_pad as u16,
        tag_len: HMAC_TAG_LEN as u16,
        reserved: [0u8; 34],
    };
    out[size_of::<Header>()..FULL_HEADER_LEN].copy_from_slice(sub.as_bytes());

    // ── 2. Random IV ──────────────────────────────────────────────

    pal.rng_fill_bytes(io, &mut out[layout.iv_off..layout.iv_off + IV_LEN])?;

    // Zero post-IV padding.
    out[layout.iv_off + IV_LEN..layout.metadata_off].fill(0);

    // ── 3. Metadata + post-metadata padding ───────────────────────

    out[layout.metadata_off..layout.metadata_off + layout.metadata_len]
        .copy_from_slice(metadata_bytes);
    out[layout.metadata_off + layout.metadata_len..layout.encrypted_key_off].fill(0);

    // ── 4. AES-CBC-256 encrypt the zero-padded plaintext ──────────
    //
    // Build the padded plaintext in a DMA scratch buffer, encrypt
    // in-place, then copy the ciphertext into the envelope.

    let enc_scratch = alloc.dma_alloc(layout.encrypted_key_len)?;
    enc_scratch[..plaintext_key.len()].copy_from_slice(plaintext_key);
    enc_scratch[plaintext_key.len()..].fill(0); // zero-pad

    let aes_key_dma = dma_copy_in(alloc, aes_key)?;
    let iv_dma = dma_copy_in(alloc, &out[layout.iv_off..layout.iv_off + IV_LEN])?;

    pal.aes_cbc_enc_dec_in_place(io, AesOp::Encrypt, aes_key_dma, enc_scratch, iv_dma, None)
        .await?;

    out[layout.encrypted_key_off..layout.encrypted_key_off + layout.encrypted_key_len]
        .copy_from_slice(enc_scratch);

    // Zero post-encrypted-key padding.
    out[layout.encrypted_key_off + layout.encrypted_key_len..layout.tag_off].fill(0);

    // ── 5. HMAC-SHA-384 tag over everything before the tag ────────

    let hmac_key_dma = dma_copy_in(alloc, hmac_key)?;
    let data_to_tag = dma_copy_in(alloc, &out[..layout.tag_off])?;
    let tag_scratch = alloc.dma_alloc(HMAC_TAG_LEN)?;

    pal.hmac_sign(
        io,
        HsmHashAlgo::Sha384,
        hmac_key_dma,
        data_to_tag,
        tag_scratch,
    )
    .await?;

    out[layout.tag_off..layout.tag_off + HMAC_TAG_LEN].copy_from_slice(tag_scratch);

    // ── 6. Wipe sensitive scratch ─────────────────────────────────

    aes_key_dma.fill(0);
    hmac_key_dma.fill(0);
    enc_scratch.fill(0);
    iv_dma.fill(0);
    data_to_tag.fill(0);
    tag_scratch.fill(0);

    Ok(())
}

// ── Public API: unmask ────────────────────────────────────────────────

/// Verify and decrypt an AES-CBC-256 + HMAC-SHA-384 MaskedKey envelope
/// in place.
///
/// Returns the number of plaintext key bytes (the encrypted_key region
/// is decrypted in place; the actual key length comes from the
/// metadata's `key_length` field, which the caller reads separately).
///
/// # Parameters
///
/// - `pal` — PAL providing AES-CBC and HMAC-SHA-384.
/// - `io` — caller's I/O context (per-IO scope).
/// - `masking_key` — 80-byte AES(32) ‖ HMAC(48) composite key.
/// - `envelope` — the complete MaskedKey wire buffer. On success, the
///   `encrypted_key` region is overwritten with the decrypted key.
/// - `alloc` — scoped allocator for intermediate DMA scratch.
///
/// # Returns
///
/// - `Ok(plaintext_len)` — number of plaintext bytes in the
///   decrypted `encrypted_key` region (= `encrypted_key_len`, which
///   may include zero-padding; the real key length is in the
///   metadata).
///
/// # Errors
///
/// - [`HsmError::DdiDecodeFailed`] — envelope is too short, header
///   is invalid, HMAC tag verification fails, or field lengths are
///   inconsistent.
/// - [`HsmError::InvalidArg`] — `masking_key` is not 80 bytes.
/// - Propagated from AES / HMAC PAL methods.
#[allow(dead_code)]
pub async fn unmask_cbc_in_place<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    masking_key: &[u8],
    envelope: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<usize>
where
    P: HsmAes + HsmHmac + 'a,
{
    if envelope.len() < FULL_HEADER_LEN + IV_LEN + HMAC_TAG_LEN {
        return Err(HsmError::DdiDecodeFailed);
    }

    // ── 1. Parse + validate header ────────────────────────────────

    let header = Header::try_ref_from_bytes(&envelope[..size_of::<Header>()])
        .map_err(|_| HsmError::DdiDecodeFailed)?;
    if header.version != FORMAT_V1 || header.algorithm != ALGO_AES_CBC_256_HMAC_384 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let sub = AesSubHeader::try_ref_from_bytes(&envelope[size_of::<Header>()..FULL_HEADER_LEN])
        .map_err(|_| HsmError::DdiDecodeFailed)?;

    // Validate field lengths.
    if sub.iv_len != IV_LEN as u16 || sub.tag_len != HMAC_TAG_LEN as u16 {
        return Err(HsmError::DdiDecodeFailed);
    }
    if sub.encrypted_key_len == 0 || sub.metadata_len == 0 {
        return Err(HsmError::DdiDecodeFailed);
    }
    // Check alignment constraints.
    if !(sub.iv_len + sub.post_iv_pad_len).is_multiple_of(4)
        || !(sub.metadata_len + sub.post_metadata_pad_len).is_multiple_of(4)
        || !(sub.encrypted_key_len + sub.post_encrypted_key_pad_len).is_multiple_of(4)
    {
        return Err(HsmError::DdiDecodeFailed);
    }

    // Compute expected total length and verify.
    let expected_len = FULL_HEADER_LEN
        + sub.iv_len as usize
        + sub.post_iv_pad_len as usize
        + sub.metadata_len as usize
        + sub.post_metadata_pad_len as usize
        + sub.encrypted_key_len as usize
        + sub.post_encrypted_key_pad_len as usize
        + sub.tag_len as usize;
    if envelope.len() != expected_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    let (aes_key, hmac_key) = split_masking_key(masking_key)?;

    // ── 2. HMAC verify ────────────────────────────────────────────

    let tag_off = envelope.len() - HMAC_TAG_LEN;
    let hmac_key_dma = dma_copy_in(alloc, hmac_key)?;
    let data_dma = dma_copy_in(alloc, &envelope[..tag_off])?;
    let expected_tag = alloc.dma_alloc(HMAC_TAG_LEN)?;

    pal.hmac_sign(
        io,
        HsmHashAlgo::Sha384,
        hmac_key_dma,
        data_dma,
        expected_tag,
    )
    .await?;

    // Compare tag bytes. DmaBuf derefs to [u8], but [u8] == DmaBuf
    // doesn't have a blanket impl, so deref both sides explicitly.
    let envelope_tag: &[u8] = &envelope[tag_off..];
    let computed_tag: &[u8] = expected_tag;
    if envelope_tag != computed_tag {
        // Wipe scratch before returning on error.
        hmac_key_dma.fill(0);
        data_dma.fill(0);
        expected_tag.fill(0);
        return Err(HsmError::DdiDecodeFailed);
    }

    // ── 3. AES-CBC-256 decrypt the encrypted_key region ───────────

    let iv_off = FULL_HEADER_LEN;
    let enc_key_off = iv_off
        + sub.iv_len as usize
        + sub.post_iv_pad_len as usize
        + sub.metadata_len as usize
        + sub.post_metadata_pad_len as usize;
    let enc_key_len = sub.encrypted_key_len as usize;

    let aes_key_dma = dma_copy_in(alloc, aes_key)?;
    let iv_dma = dma_copy_in(alloc, &envelope[iv_off..iv_off + IV_LEN])?;
    let enc_scratch = alloc.dma_alloc(enc_key_len)?;
    enc_scratch.copy_from_slice(&envelope[enc_key_off..enc_key_off + enc_key_len]);

    pal.aes_cbc_enc_dec_in_place(io, AesOp::Decrypt, aes_key_dma, enc_scratch, iv_dma, None)
        .await?;

    // Copy decrypted data back into the envelope.
    envelope[enc_key_off..enc_key_off + enc_key_len].copy_from_slice(enc_scratch);

    // ── 4. Wipe sensitive scratch ─────────────────────────────────

    aes_key_dma.fill(0);
    hmac_key_dma.fill(0);
    iv_dma.fill(0);
    enc_scratch.fill(0);
    data_dma.fill(0);
    expected_tag.fill(0);

    Ok(enc_key_len)
}

// ── Public API: metadata helpers ──────────────────────────────────────

/// Parameters for constructing a [`DdiMaskedKeyMetadata`] blob.
///
/// Passed to [`build_metadata`], [`metadata_encoded_len`], and
/// [`encode_metadata`]. The caller is responsible for sourcing the
/// values from the PAL (e.g. `pal.current_svn()`,
/// `pal.current_bks2_index()`) rather than hardcoding them.
pub struct MetadataParams<'a> {
    /// Firmware security version number.
    pub svn: u64,
    /// Key algorithm / type tag.
    pub key_type: DdiKeyType,
    /// Key attributes blob (typically 32 zero bytes for BK3 / BK_BOOT).
    pub key_attributes: &'a [u8],
    /// BKS2 index (`None` if not applicable).
    pub bks2_index: Option<u16>,
    /// Optional key tag.
    pub key_tag: Option<u16>,
    /// Human-readable key label (e.g., `b"BK3"`, `b"BKBoot"`).
    pub label: &'a [u8],
    /// Plaintext key length in bytes (stored in the metadata so the
    /// decoder knows how much of the encrypted_key region is real
    /// data vs. zero-padding).
    pub key_length: u16,
}

/// Build a [`DdiMaskedKeyMetadata`] from caller-supplied parameters.
pub fn build_metadata<'a>(params: &MetadataParams<'a>) -> DdiMaskedKeyMetadata<'a> {
    DdiMaskedKeyMetadata {
        svn: Some(params.svn),
        key_type: params.key_type,
        key_attributes: DdiMaskedKeyAttributes {
            blob: params.key_attributes,
        },
        bks2_index: params.bks2_index,
        key_tag: params.key_tag,
        key_label: params.label,
        key_length: params.key_length,
    }
}

/// Compute the MBOR-encoded length of a [`DdiMaskedKeyMetadata`]
/// built by [`build_metadata`] without materializing any buffer.
///
/// Used to pre-compute envelope sizes for [`cbc_envelope_len`] before
/// allocating the response buffer or scoped scratch.
pub fn metadata_encoded_len(params: &MetadataParams<'_>) -> usize {
    let md = build_metadata(params);
    let mut acc = MborLenAccumulator::default();
    md.mbor_len(&mut acc);
    acc.len()
}

/// MBOR-encode a [`DdiMaskedKeyMetadata`] into `out` and return the
/// number of bytes written.
///
/// The caller must ensure `out.len() >= metadata_encoded_len(params)`.
pub fn encode_metadata(out: &mut [u8], params: &MetadataParams<'_>) -> HsmResult<usize> {
    let md = build_metadata(params);
    let mut enc = MborEncoder::new(out);
    md.mbor_encode(&mut enc)?;
    Ok(enc.position())
}

// ── Unit tests ────────────────────────────────────────────────────────

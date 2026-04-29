// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MaskedKey envelope codec (AES-CBC-256 + HMAC-SHA-384).
//!
//! Encodes / decodes the wire format defined by
//! `azihsm_ddi_types::masked_key` (host SDK) and
//! `mcr-hsm/.../masked_key/{encode,decode}.rs` (production fw).
//!
//! # Wire format
//!
//! All `u16` fields are little-endian. Total length depends on the
//! plaintext key length and metadata length.
//!
//! ```text
//! Offset  Length  Field
//! ──────  ──────  ─────────────────────────────────────────
//!      0       2  version (u16 LE)
//!      2       2  algorithm (u16 LE) — 1 = AesCbc256Hmac384
//!      4       2  iv_len (u16 LE) — 16 for AES-CBC
//!      6       2  post_iv_pad_len (u16 LE) — 0 (16 mod 4 = 0)
//!      8       2  metadata_len (u16 LE)
//!     10       2  post_metadata_pad_len (u16 LE) — pad to 4 bytes
//!     12       2  encrypted_key_len (u16 LE) — pad to 16 bytes
//!     14       2  post_encrypted_key_pad_len (u16 LE) — 0
//!     16       2  tag_len (u16 LE) — 48 for HMAC-SHA-384
//!     18      34  reserved (zero-filled)
//!     52      16  IV
//!     68       m  metadata (MBOR-encoded DdiMaskedKeyMetadata)
//!     68+m     p  post-metadata padding (zero-filled)
//!     68+m+p   e  encrypted_key (AES-CBC-256 ciphertext)
//!     68+m+p+e 0  post-encrypted-key padding (always 0 here)
//!     end-48  48  HMAC-SHA-384 tag
//! ```
//!
//! The HMAC tag covers everything from offset 0 up to (but not
//! including) the tag itself.

use azihsm_fw_hsm_pal_traits::*;

use crate::lm_key_derive::split_aes_hmac_key;

// ── Wire-format constants ─────────────────────────────────────────────

/// Bytes consumed by the [`MaskedKeyHeader`]: version + algorithm.
pub const MASKED_KEY_HEADER_LEN: usize = 4;

/// Bytes consumed by the [`MaskedKeyAesHeader`]: 7 × u16 + 34 reserved.
pub const MASKED_KEY_AES_HEADER_LEN: usize = 50;

/// Bytes consumed by the fixed prefix (`MaskedKeyHeader` +
/// `MaskedKeyAesHeader`).
pub const MASKED_KEY_PREFIX_LEN: usize = MASKED_KEY_HEADER_LEN + MASKED_KEY_AES_HEADER_LEN;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-CBC IV size in bytes.
pub const AES_CBC_IV_SIZE: usize = 16;

/// HMAC-SHA-384 tag and key size in bytes.
pub const HMAC384_SIZE: usize = 48;

/// Wire-format version of the MaskedKey envelope this codec emits.
pub const MASKED_KEY_VERSION: u16 = 1;

/// Algorithm identifier for AES-CBC-256 + HMAC-SHA-384 envelopes.
const ALGO_AES_CBC_256_HMAC384: u16 = 1;

// ── Layout helpers ────────────────────────────────────────────────────

/// Compute the total encoded length of an AES-CBC-256-HMAC-384
/// envelope holding a `plaintext_key_len`-byte key and a
/// `metadata_len`-byte metadata blob.
///
/// Padding rules (from `azihsm_ddi_types::masked_key::calculate_layout`):
/// * `post_iv_pad_len = next_multiple_of(iv_len, 4) - iv_len`
///   (zero for AES-CBC since `iv_len = 16`).
/// * `post_metadata_pad_len = next_multiple_of(metadata_len, 4) - metadata_len`.
/// * `post_encrypted_key_pad_len = next_multiple_of(encrypted_key_len, 4) - encrypted_key_len`
///   (zero since `encrypted_key_len` is always a multiple of 16).
/// * `encrypted_key_len = next_multiple_of(plaintext_key_len, AES_BLOCK_SIZE)`.
pub fn aes_cbc_envelope_len(metadata_len: usize, plaintext_key_len: usize) -> usize {
    let post_metadata_pad = metadata_len.next_multiple_of(4) - metadata_len;
    let encrypted_key_len = plaintext_key_len.next_multiple_of(AES_BLOCK_SIZE);
    MASKED_KEY_PREFIX_LEN
        + AES_CBC_IV_SIZE          // IV
        + 0                        // post_iv_pad (16 mod 4 = 0)
        + metadata_len
        + post_metadata_pad
        + encrypted_key_len
        + 0                        // post_encrypted_key_pad (multiple of 4)
        + HMAC384_SIZE // tag
}

/// Cached offsets / lengths derived from a layout calculation. Used to
/// avoid recomputing slice ranges in [`encode_aes_cbc_256_hmac384`].
struct Layout {
    metadata_len: usize,
    post_metadata_pad_len: usize,
    encrypted_key_len: usize,
}

impl Layout {
    fn for_aes_cbc(metadata_len: usize, plaintext_key_len: usize) -> Self {
        Self {
            metadata_len,
            post_metadata_pad_len: metadata_len.next_multiple_of(4) - metadata_len,
            encrypted_key_len: plaintext_key_len.next_multiple_of(AES_BLOCK_SIZE),
        }
    }

    /// Offset of the IV in the envelope.
    const fn iv_offset(&self) -> usize {
        MASKED_KEY_PREFIX_LEN
    }
    /// Offset of the metadata in the envelope.
    const fn metadata_offset(&self) -> usize {
        self.iv_offset() + AES_CBC_IV_SIZE
    }
    /// Offset of the encrypted key in the envelope.
    fn encrypted_key_offset(&self) -> usize {
        self.metadata_offset() + self.metadata_len + self.post_metadata_pad_len
    }
    /// Offset of the HMAC tag in the envelope.
    fn tag_offset(&self) -> usize {
        self.encrypted_key_offset() + self.encrypted_key_len
    }
    /// Total envelope length.
    fn total_len(&self) -> usize {
        self.tag_offset() + HMAC384_SIZE
    }
}

// ── Header serialization helpers ──────────────────────────────────────

#[inline]
fn write_u16_le(dst: &mut [u8], v: u16) {
    dst[0] = (v & 0xFF) as u8;
    dst[1] = ((v >> 8) & 0xFF) as u8;
}

/// Write the [`MaskedKeyHeader`] at offset 0 and the
/// [`MaskedKeyAesHeader`] immediately after.
fn write_headers(
    out: &mut [u8],
    metadata_len: u16,
    encrypted_key_len: u16,
    post_metadata_pad_len: u16,
) {
    // MaskedKeyHeader.
    write_u16_le(&mut out[0..2], MASKED_KEY_VERSION);
    write_u16_le(&mut out[2..4], ALGO_AES_CBC_256_HMAC384);
    // MaskedKeyAesHeader.
    write_u16_le(&mut out[4..6], AES_CBC_IV_SIZE as u16); // iv_len
    write_u16_le(&mut out[6..8], 0); // post_iv_pad_len
    write_u16_le(&mut out[8..10], metadata_len);
    write_u16_le(&mut out[10..12], post_metadata_pad_len);
    write_u16_le(&mut out[12..14], encrypted_key_len);
    write_u16_le(&mut out[14..16], 0); // post_encrypted_key_pad_len
    write_u16_le(&mut out[16..18], HMAC384_SIZE as u16); // tag_len
    out[18..18 + 34].fill(0); // reserved
}

// ── Encoder ───────────────────────────────────────────────────────────

/// Encode a key into an AES-CBC-256 + HMAC-SHA-384 MaskedKey envelope.
///
/// Mirrors mcr-hsm `MaskedKey::encode` for the `AesCbc256Hmac384`
/// algorithm.
///
/// # Parameters
/// * `pal`               — PAL providing AES, HMAC, and RNG.
/// * `plaintext_key`     — The key bytes to encrypt. Length must be a
///                         multiple of [`AES_BLOCK_SIZE`].
/// * `masking_key`       — The 80-byte AES‖HMAC composite masking key
///                         (output of [`crate::lm_key_derive::bk_boot_key_gen`]
///                         or similar).
/// * `metadata_bytes`    — The pre-MBOR-encoded metadata to embed in
///                         the envelope. Integrity-protected, not
///                         encrypted.
/// * `out`               — Destination buffer. Must be exactly
///                         [`aes_cbc_envelope_len`]`(metadata_bytes.len(),
///                         plaintext_key.len())` bytes.
pub async fn encode_aes_cbc_256_hmac384<P: HsmPal>(
    pal: &P,
    plaintext_key: &[u8],
    masking_key: &[u8],
    metadata_bytes: &[u8],
    out: &mut [u8],
) -> HsmResult<()> {
    if plaintext_key.is_empty() || plaintext_key.len() % AES_BLOCK_SIZE != 0 {
        return Err(HsmError::InvalidArg);
    }
    let layout = Layout::for_aes_cbc(metadata_bytes.len(), plaintext_key.len());
    if out.len() != layout.total_len() {
        return Err(HsmError::InvalidArg);
    }

    let (aes_key, hmac_key) = split_aes_hmac_key(masking_key)?;

    // 1. Headers.
    write_headers(
        out,
        layout.metadata_len as u16,
        layout.encrypted_key_len as u16,
        layout.post_metadata_pad_len as u16,
    );

    // 2. Random IV.
    let iv_off = layout.iv_offset();
    pal.rng_fill_bytes(&mut out[iv_off..iv_off + AES_CBC_IV_SIZE])?;

    // 3. Copy metadata + zero post-metadata padding (the padding is
    //    integrity-protected by the HMAC).
    let md_off = layout.metadata_offset();
    out[md_off..md_off + layout.metadata_len].copy_from_slice(metadata_bytes);
    out[md_off + layout.metadata_len..md_off + layout.metadata_len + layout.post_metadata_pad_len]
        .fill(0);

    // 4. AES-CBC encrypt plaintext_key into the encrypted_key slot.
    //    aes_cbc_enc_dec wants the IV mutable (it's updated to the
    //    final ciphertext block for chaining); we don't care about that
    //    final state, but we must NOT mutate the in-envelope IV that
    //    the HMAC will cover. Copy to a stack scratch first.
    let enc_off = layout.encrypted_key_offset();
    let mut iv_scratch = [0u8; AES_CBC_IV_SIZE];
    iv_scratch.copy_from_slice(&out[iv_off..iv_off + AES_CBC_IV_SIZE]);
    {
        // Split borrows: we read plaintext_key (caller-owned) and write
        // into out[enc_off..enc_off + encrypted_key_len].
        let (head, tail) = out.split_at_mut(enc_off);
        let _ = head; // unused (pre-encrypted-key region)
        let cipher_slot = &mut tail[..layout.encrypted_key_len];
        pal.aes_cbc_enc_dec(aes_key, true, &mut iv_scratch, plaintext_key, cipher_slot)
            .await?;
    }

    // 5. HMAC-SHA-384 over everything except the tag itself.
    let tag_off = layout.tag_offset();
    let (data_to_tag, tag_slot) = out.split_at_mut(tag_off);
    pal.hmac_sign(hmac_key, data_to_tag, tag_slot).await?;

    Ok(())
}

// ── Decoder ───────────────────────────────────────────────────────────

/// Decode an AES-CBC-256 + HMAC-SHA-384 MaskedKey envelope.
///
/// Verifies the HMAC tag, then decrypts the encrypted key into
/// `plaintext_out`. Used by `EstablishCredential` (later iteration) to
/// recover BK_BOOT from `masked_bk_boot` and BK3 from `masked_bk3`.
///
/// `plaintext_out.len()` must equal the expected plaintext key length.
/// Internally the envelope's `encrypted_key_len` is rounded up to a
/// 16-byte boundary; the trailing zero-padding bytes are dropped from
/// the decryption output.
#[allow(dead_code)] // exercised in a later iteration (EstablishCredential)
pub async fn decode_aes_cbc_256_hmac384<P: HsmPal>(
    pal: &P,
    masking_key: &[u8],
    envelope: &[u8],
    plaintext_out: &mut [u8],
) -> HsmResult<()> {
    if envelope.len() < MASKED_KEY_PREFIX_LEN + AES_CBC_IV_SIZE + HMAC384_SIZE {
        return Err(HsmError::DdiDecodeFailed);
    }

    // Parse the AES header to recover layout fields.
    let metadata_len = u16::from_le_bytes([envelope[8], envelope[9]]) as usize;
    let encrypted_key_len = u16::from_le_bytes([envelope[12], envelope[13]]) as usize;
    let layout = Layout {
        metadata_len,
        post_metadata_pad_len: metadata_len.next_multiple_of(4) - metadata_len,
        encrypted_key_len,
    };

    if envelope.len() != layout.total_len() {
        return Err(HsmError::DdiDecodeFailed);
    }
    if plaintext_out.len() > encrypted_key_len {
        return Err(HsmError::InvalidArg);
    }

    let (aes_key, hmac_key) = split_aes_hmac_key(masking_key)?;

    // 1. HMAC verify (constant-time inside the PAL).
    let tag_off = layout.tag_offset();
    let (data_to_tag, tag_slice) = envelope.split_at(tag_off);
    if !pal.hmac_verify(hmac_key, data_to_tag, tag_slice).await? {
        return Err(HsmError::DdiDecodeFailed);
    }

    // 2. AES-CBC decrypt into a stack scratch sized to the full
    //    encrypted_key_len (multiple of 16); then copy out the leading
    //    `plaintext_out.len()` bytes.
    if encrypted_key_len > MAX_DECRYPT_SCRATCH {
        return Err(HsmError::InvalidArg);
    }
    let mut iv_scratch = [0u8; AES_CBC_IV_SIZE];
    iv_scratch.copy_from_slice(&envelope[layout.iv_offset()..layout.iv_offset() + AES_CBC_IV_SIZE]);
    let mut scratch = [0u8; MAX_DECRYPT_SCRATCH];
    pal.aes_cbc_enc_dec(
        aes_key,
        false,
        &mut iv_scratch,
        &envelope[layout.encrypted_key_offset()..layout.encrypted_key_offset() + encrypted_key_len],
        &mut scratch[..encrypted_key_len],
    )
    .await?;
    plaintext_out.copy_from_slice(&scratch[..plaintext_out.len()]);

    Ok(())
}

/// Maximum plaintext key length the [`decode_aes_cbc_256_hmac384`]
/// stack scratch can handle. 256 bytes is comfortably above the
/// largest currently used key (BK_BOOT = 80, BK3 = 48).
const MAX_DECRYPT_SCRATCH: usize = 256;

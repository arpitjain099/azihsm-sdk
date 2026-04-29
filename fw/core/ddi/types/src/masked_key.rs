// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Masked-key wire-format DDI types.
//!
//! Mirrors the on-the-wire portion of `azihsm_ddi_types::masked_key` —
//! just the types that appear inside DDI request/response maps. The
//! actual masked-key envelope codec (header structs, layout,
//! encrypt/decrypt) lives in `fw/core/lib/src/masked_key.rs` because
//! it's a firmware-internal implementation detail, not a DDI protocol
//! type.

use azihsm_fw_ddi_derive::Ddi;
use open_enum::open_enum;

use crate::*;

/// Algorithm used to mask a key in transit / at rest.
///
/// Only `AesCbc256Hmac384` (= 1) is currently in active use. Matches the
/// host SDK's `azihsm_ddi_types::MaskingKeyAlgorithm`.
#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum MaskingKeyAlgorithm {
    /// AES-256 in CBC mode with HMAC-SHA-384 for integrity.
    AesCbc256Hmac384 = 1,

    /// AES-256 in GCM mode (reserved; not yet implemented in fw).
    AesGcm256 = 2,
}

/// Per-key opaque attributes carried in masked-key metadata.
///
/// Wraps a 32-byte attribute blob defined per `key_type`. The codec
/// treats the blob as opaque.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiMaskedKeyAttributes<'a> {
    /// Opaque per-key attributes — exactly 32 bytes.
    #[ddi(id = 1, len = 32)]
    pub blob: &'a [u8],
}

/// Metadata payload that lives inside the MaskedKey envelope.
///
/// MBOR-encoded; the encoded bytes are integrity-protected by the
/// envelope's HMAC tag but not encrypted. Mirrors the host SDK's
/// `azihsm_ddi_types::DdiMaskedKeyMetadata` field-for-field.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiMaskedKeyMetadata<'a> {
    /// Security version number.
    #[ddi(id = 1)]
    pub svn: Option<u64>,

    /// The kind of key being masked (e.g. `Secret384`).
    #[ddi(id = 2)]
    pub key_type: DdiKeyType,

    /// Opaque per-key attributes (32-byte blob).
    #[ddi(id = 3)]
    pub key_attributes: DdiMaskedKeyAttributes<'a>,

    /// Optional BKS2 index (used for partition-bound keys).
    #[ddi(id = 4)]
    pub bks2_index: Option<u16>,

    /// Optional caller-defined tag for the key.
    #[ddi(id = 5)]
    pub key_tag: Option<u16>,

    /// Human-readable label, ≤ 128 bytes.
    #[ddi(id = 6, max_len = 128)]
    pub key_label: &'a [u8],

    /// Length of the key (in bytes) once unmasked.
    #[ddi(id = 7)]
    pub key_length: u16,
}

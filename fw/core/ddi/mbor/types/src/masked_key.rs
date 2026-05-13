// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MBOR types for MaskedKey metadata (used by the MaskedKey envelope
//! codec in `azihsm_fw_core_crypto_key_mask`).

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

/// Metadata embedded in a MaskedKey envelope.
///
/// Integrity-protected (covered by the envelope's HMAC tag) but not
/// encrypted. Mirrors `azihsm_ddi_types::DdiMaskedKeyMetadata`.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiMaskedKeyMetadata<'a> {
    #[ddi(id = 1)]
    pub svn: Option<u64>,

    #[ddi(id = 2)]
    pub key_type: DdiKeyType,

    #[ddi(id = 3)]
    pub key_attributes: DdiMaskedKeyAttributes<'a>,

    #[ddi(id = 4)]
    pub bks2_index: Option<u16>,

    #[ddi(id = 5)]
    pub key_tag: Option<u16>,

    #[ddi(id = 6, max_len = 128)]
    pub key_label: &'a [u8],

    #[ddi(id = 7)]
    pub key_length: u16,
}

/// Key attributes blob embedded in [`DdiMaskedKeyMetadata`].
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiMaskedKeyAttributes<'a> {
    #[ddi(id = 1, max_len = 64)]
    pub blob: &'a [u8],
}

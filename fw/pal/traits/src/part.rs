// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management types and traits.
//!
//! Defines the [`PartitionManager`] trait for querying and managing HSM
//! partitions. Each partition represents a distinct host controller interface
//! identified by [`HsmPartId`].

use super::*;

/// Opaque identity blob for a partition.
pub type PartId<'a> = &'a [u8];

/// Represents the current state of a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartState {
    /// Partition slot is not allocated. No resources assigned.
    Unallocated,

    /// Partition is allocated with resources and identity key pair, but
    /// internal crypto keys (establish-cred, session-enc) and nonce
    /// have not been created yet.
    Allocated,

    /// Partition is fully operational. Internal keys and nonce are
    /// present. DDI operations can proceed.
    Enabled,

    /// Partition has been disabled. Internal keys, nonce, vault keys,
    /// and sessions are cleared, but resources and identity remain.
    /// Can be re-enabled via `part_enable`.
    Disabled,
}

/// Partition manager interface.
///
/// Provides methods for querying partition status, resource allocation, and
/// identity credentials. Each partition is addressed by [`HsmPartId`].
pub trait HsmPartitionManager {
    /// Returns whether the partition identified by `pid` is enabled.
    ///
    /// # Parameters
    /// - `pid` — Partition identifier.
    ///
    /// # Returns
    /// The current [`PartState`] of the partition identified by `pid`.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_state(&self, pid: HsmPartId) -> HsmResult<PartState>;

    /// Returns the resource count allocated to the given partition.
    ///
    /// # Parameters
    /// - `pid` — Partition identifier.
    ///
    /// # Returns
    /// The number of resources allocated to the partition.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_res_count(&self, pid: HsmPartId) -> HsmResult<u8>;

    /// Returns the opaque identity blob for the given partition.
    ///
    /// # Parameters
    /// - `pid` — Partition identifier.
    ///
    /// # Returns
    /// A borrowed byte slice ([`PartId`]) containing the partition's identity.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_id(&self, pid: HsmPartId) -> HsmResult<PartId<'_>>;

    /// Returns the vault key ID for the partition's identity ECC-384 key.
    ///
    /// The private key is stored in the vault as `Ecc384Private` with
    /// `sign + local + internal` attributes.
    fn part_id_key_id(&self, pid: HsmPartId) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded public key for the partition's identity key.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    fn part_id_pub_key(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns the establish-credential encryption key ID.
    ///
    /// Returns `None` if the key has been cleared (one-time use pattern)
    /// or if the partition is not in [`Enabled`](PartState::Enabled) state.
    fn part_establish_cred_key_id(&self, pid: HsmPartId) -> HsmResult<Option<HsmKeyId>>;

    /// Returns the DER-encoded public key for establish-credential encryption.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    /// Returns 0 if the key has been cleared.
    fn part_establish_cred_pub_key(
        &self,
        pid: HsmPartId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize>;

    /// Clear the establish-credential encryption key from the vault.
    ///
    /// After clearing, [`part_establish_cred_key_id`](Self::part_establish_cred_key_id)
    /// returns `None`.  This implements the one-time-use pattern: the
    /// core calls this after credential establishment completes.
    ///
    /// Idempotent — calling on an already-cleared key succeeds silently.
    fn part_clear_establish_cred_key(&self, pid: HsmPartId) -> HsmResult<()>;

    /// Returns the session encryption key ID.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition is not [`Enabled`](PartState::Enabled).
    fn part_session_enc_key_id(&self, pid: HsmPartId) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded public key for session encryption.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    fn part_session_enc_pub_key(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns the 32-byte random nonce for the partition.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition is not [`Enabled`](PartState::Enabled).
    fn part_nonce(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Refresh (regenerate) the partition nonce from the RNG.
    ///
    /// Called after credential establishment or session open to ensure
    /// nonce freshness.
    fn part_nonce_refresh(&self, pid: HsmPartId) -> HsmResult<()>;

    /// Read the sealed-BK3 blob previously written via
    /// [`part_set_sealed_bk3`](Self::part_set_sealed_bk3).
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into
    /// `buf` and return the number of bytes written.
    ///
    /// The blob is opaque to the firmware — the host owns its
    /// interpretation. Persists across `disable`/`enable`; cleared by
    /// `part_free`.
    ///
    /// # Errors
    /// - [`HsmError::SealedBk3NotPresent`] — the blob has not yet been set.
    /// - [`HsmError::InvalidArg`] — `pid` is out of range, the
    ///   partition is not allocated, or `out` is `Some(buf)` and `buf`
    ///   is too small.
    fn part_sealed_bk3(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Store a sealed-BK3 blob into per-partition storage.
    ///
    /// Single-shot: subsequent calls fail with
    /// [`HsmError::SealedBk3AlreadySet`] until the partition is freed
    /// and re-allocated.
    ///
    /// # Errors
    /// - [`HsmError::SealedBk3TooLarge`] — `data.len()` exceeds the
    ///   per-partition storage size.
    /// - [`HsmError::SealedBk3AlreadySet`] — the blob has already been set.
    /// - [`HsmError::InvalidArg`] — `pid` is out of range or the
    ///   partition is not allocated.
    fn part_set_sealed_bk3(&self, pid: HsmPartId, data: &[u8]) -> HsmResult<()>;

    /// Read the masked-BK_BOOT envelope previously written via
    /// [`part_set_masked_bk_boot`](Self::part_set_masked_bk_boot).
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into
    /// `buf` and return the number of bytes written.
    ///
    /// The blob is opaque to the firmware *core* — its contents are
    /// owned by the masked-key codec in `fw/core/lib/src/masked_key.rs`.
    /// Persists across `disable`/`enable`; cleared on `part_free`.
    ///
    /// # Errors
    /// - [`HsmError::KeyNotFound`] — `InitBk3` has not yet run for this
    ///   partition.
    /// - [`HsmError::InvalidArg`] — `pid` is out of range, the
    ///   partition is not allocated, or `out` is `Some(buf)` and `buf`
    ///   is too small.
    fn part_masked_bk_boot(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Store the masked-BK_BOOT envelope produced by `InitBk3`.
    ///
    /// Single-shot: subsequent calls fail with
    /// [`HsmError::Bk3AlreadyInitialized`] (matches mcr-hsm
    /// `HsmErr::Bk3AlreadyInitialized`).
    ///
    /// # Errors
    /// - [`HsmError::Bk3AlreadyInitialized`] — `InitBk3` already
    ///   completed for this partition.
    /// - [`HsmError::InvalidArg`] — `pid` is out of range, the
    ///   partition is not allocated, or `data` exceeds the
    ///   per-partition storage size.
    fn part_set_masked_bk_boot(&self, pid: HsmPartId, data: &[u8]) -> HsmResult<()>;

    /// Borrow the user credential previously stored by
    /// `EstablishCredential`.
    ///
    /// Returns `(user_id (16B), pin (16B), host_pub_key (96B PKA-native LE))`.
    /// Used by `OpenSession` to authenticate session-credential
    /// requests against the previously-established user.
    ///
    /// Cleared by `disable` / `free`.
    ///
    /// # Errors
    /// - [`HsmError::InvalidAppCredentials`] — no credential has been
    ///   established for this partition.
    /// - [`HsmError::InvalidArg`] — `pid` is out of range or the
    ///   partition is not allocated.
    fn part_user_credential(&self, pid: HsmPartId) -> HsmResult<(&[u8; 16], &[u8; 16], &[u8; 96])>;

    /// Store a freshly-decrypted user credential into partition state.
    ///
    /// Single-shot: subsequent calls fail with
    /// [`HsmError::VaultAppLimitReached`] until the partition is
    /// disabled (which clears the credential) or freed.
    ///
    /// # Errors
    /// - [`HsmError::VaultAppLimitReached`] — credential already established.
    /// - [`HsmError::InvalidArg`] — `pid` is out of range or the
    ///   partition is not allocated.
    fn part_set_user_credential(
        &self,
        pid: HsmPartId,
        id: &[u8; 16],
        pin: &[u8; 16],
        pub_key: &[u8; 96],
    ) -> HsmResult<()>;

    /// Returns the vault key ID of the RSA-2k unwrapping key.
    ///
    /// Generated during `part_enable`. Used by `GetUnwrappingKey` and
    /// `RsaUnwrap`.
    fn part_unwrapping_key_id(&self, pid: HsmPartId) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded RSA public key for unwrapping.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy.
    fn part_unwrapping_pub_key(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize>;
}

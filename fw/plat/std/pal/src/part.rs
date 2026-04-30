// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management for the standard (host-native) PAL.
//!
//! Implements the [`HsmPartitionManager`] trait from
//! `azihsm_fw_hsm_pal_traits` for [`StdHsmPal`] and provides sideband
//! partition allocation/deallocation via [`PartCommand`].
//!
//! ## Architecture
//!
//! The partition table lives on the Embassy thread inside [`StdHsmPal`],
//! stored in an [`UnsafeCell`] to allow the `&self` trait methods to
//! return borrowed slices tied to the PAL's lifetime. This is safe
//! because the Embassy executor is single-threaded — no concurrent
//! access is possible.
//!
//! Sideband commands ([`PartCommand::Alloc`] / [`PartCommand::Free`])
//! arrive from the user-facing [`StdHsm`] via an `async_channel` and
//! are processed by a dedicated Embassy task. These commands mutate
//! the partition table through [`part_alloc_internal`] and
//! [`part_free_internal`], which obtain `&mut` access through the
//! `UnsafeCell`. Because Embassy tasks only interleave at `.await`
//! points and the trait read methods are synchronous, no aliasing
//! violations can occur.
//!
//! ## Partition lifecycle
//!
//! ```text
//! Disabled ──► part_alloc ──► Uninitialized ──► (future: Initialized)
//!    ▲                              │
//!    └────────── part_free ─────────┘
//! ```
//!
//! ## Resource allocation
//!
//! Each partition is assigned a **resource bitmask** (`u128`) where each
//! set bit represents one vault table (resource).  There are 65 total
//! resources (bits 0..64).  A global bitmask on [`PartitionTable`]
//! tracks which resources are already allocated across all partitions
//! to prevent double-allocation.  `popcount(res_mask)` gives the
//! partition's table count (= what [`part_res_count`] returns).
//!
//! [`StdHsm`]: azihsm_fw_hsm_std::StdHsm
//! [`part_alloc_internal`]: StdHsmPal::part_alloc_internal
//! [`part_free_internal`]: StdHsmPal::part_free_internal

use azihsm_crypto::*;

use super::*;
use crate::cert::MAX_CERT_DER_LEN;
use crate::drivers::session::SessionTable;
use crate::drivers::vault::KeyVault;

/// Total number of partitions supported by the HSM.
pub const NUM_PARTITIONS: usize = 65;

/// Maximum total resources across all partitions.
pub const MAX_RESOURCES: u8 = 65;

/// Length of the per-partition random nonce in bytes.
const NONCE_LEN: usize = 32;

/// Length of a partition's random identity blob in bytes.
const PART_ID_LEN: usize = 16;

/// Size of a single P-384 coordinate (x or y) in bytes.
const P384_COORD_SIZE: usize = 48;

/// Size of the raw public key (x ∥ y) in bytes.
pub(crate) const P384_PUB_KEY_LEN: usize = P384_COORD_SIZE * 2;

/// Maximum size of a sealed-BK3 blob in bytes (matches the sim's
/// `SEALED_BK3_SIZE` and the host SDK's `MborByteArray<1024>` upper
/// bound; we adopt the smaller mcr-hsm/sim limit).
pub(crate) const SEALED_BK3_SIZE: usize = 512;

/// Maximum size of the masked BK_BOOT blob in bytes.
///
/// The plaintext BK_BOOT is 80 bytes (AES‖HMAC). After MaskedKey
/// envelope encoding (header + AES header + IV + metadata + ciphertext
/// + HMAC tag), the actual size is ~250 bytes for typical metadata.
/// 512 leaves comfortable headroom and matches [`SEALED_BK3_SIZE`].
pub(crate) const MASKED_BK_BOOT_SIZE: usize = 512;

/// Length of the user ID stored after `EstablishCredential`.
pub(crate) const APP_ID_LEN: usize = 16;

/// Length of the user PIN stored after `EstablishCredential`.
pub(crate) const APP_PIN_LEN: usize = 16;

/// A single partition's state and cryptographic material.
///
/// Each partition entry holds all per-partition data in fixed-size
/// inline buffers.  This avoids heap allocations, simplifies the
/// lifetime model for borrowed trait returns, and mirrors the
/// fixed-slot storage model used by the hardware HSM.
///
/// ## Memory layout
///
/// | Field | Size | Description |
/// |-------|------|-------------|
/// | `state` | 1 B | Lifecycle state (`Disabled` / `Uninitialized`) |
/// | `res_mask` | 16 B | Resource bitmask (each bit = one vault table) |
/// | `id` | 16 B | Random identity blob |
/// | `pub_key` | 96 B | Raw P-384 public key (x ∥ y) |
/// | `priv_key_der` | 256 B | PKCS#8 DER-encoded P-384 private key |
/// | `leaf_cert` | 2 KB | Cached DER-encoded partition leaf certificate |
/// | `session_table` | 2 B | Bitmask session allocator |
///
/// ## Zeroization
///
/// When a partition is freed via [`part_free_internal`], all
/// cryptographic material (`id`, `pub_key`, `priv_key_der`,
/// `leaf_cert`) is explicitly zeroed before the state transitions
/// back to `Disabled`.
///
/// [`part_free_internal`]: StdHsmPal::part_free_internal
pub(crate) struct PartitionEntry {
    /// Current lifecycle state.
    pub(crate) state: PartState,

    /// Resource bitmask — each set bit corresponds to one vault table
    /// assigned to this partition.  `count_ones()` gives the table count.
    res_mask: u128,

    /// 16-byte random identity blob, generated on allocation.
    id: [u8; PART_ID_LEN],

    /// Vault key ID for the partition's identity ECC-384 private key.
    id_key_id: Option<HsmKeyId>,

    /// Raw public key coordinates (x ∥ y, 96 bytes) for identity key.
    pub(crate) id_pub_key: [u8; P384_PUB_KEY_LEN],

    /// Cached DER-encoded partition leaf certificate (lazily generated).
    pub(crate) leaf_cert: [u8; MAX_CERT_DER_LEN],

    /// Length of valid data in `leaf_cert` (0 = not yet generated).
    pub(crate) leaf_cert_len: usize,

    /// Per-partition session table for tracking allocated sessions.
    pub(crate) session_table: SessionTable,

    /// Per-partition key vault — number of tables determined by
    /// `res_mask.count_ones()` at allocation time.
    pub(crate) vault: KeyVault,

    /// Vault key ID for the establish-credential encryption ECC-384 key.
    /// `None` before enable or after one-time clear.
    pub(crate) establish_cred_key_id: Option<HsmKeyId>,

    /// DER-encoded public key for establish-credential encryption.
    establish_cred_pub_key: [u8; P384_PUB_KEY_LEN],

    /// Vault key ID for the session encryption ECC-384 key.
    /// `None` before enable.
    pub(crate) session_enc_key_id: Option<HsmKeyId>,

    /// Raw public key coordinates (x ∥ y) for session encryption.
    session_enc_pub_key: [u8; P384_PUB_KEY_LEN],

    /// 32-byte random nonce, generated on enable and refreshable.
    pub(crate) nonce: [u8; NONCE_LEN],

    /// Sealed BK3 blob (provisioned by `SetSealedBk3`, read by
    /// `GetSealedBk3`).  The blob is opaque to the firmware — the host
    /// is free to seal whatever it wants, up to [`SEALED_BK3_SIZE`]
    /// bytes.  Persists across `disable`/`enable`; cleared on
    /// `part_free`.
    pub(crate) sealed_bk3: [u8; SEALED_BK3_SIZE],

    /// Length of valid data in [`sealed_bk3`](Self::sealed_bk3).
    /// `0` means "not yet set"; a `SetSealedBk3` then succeeds, and
    /// subsequent attempts return [`HsmError::SealedBk3AlreadySet`].
    pub(crate) sealed_bk3_len: u32,

    /// Masked BK_BOOT blob, set once by the first successful
    /// `InitBk3`. Subsequent `InitBk3` calls return
    /// [`HsmError::Bk3AlreadyInitialized`]. Persists across
    /// disable/enable; cleared on `part_free`.
    pub(crate) masked_bk_boot: [u8; MASKED_BK_BOOT_SIZE],

    /// Length of valid data in [`masked_bk_boot`](Self::masked_bk_boot).
    /// `0` means "InitBk3 has not yet run for this partition".
    pub(crate) masked_bk_boot_len: u32,

    /// User credential established by `EstablishCredential`.
    pub(crate) app_user_id: [u8; APP_ID_LEN],
    pub(crate) app_pin: [u8; APP_PIN_LEN],
    /// Host's ephemeral ECC P-384 public key from `EstablishCredential`.
    /// Stored as PKA-native `LE X || LE Y` (96 bytes) and reused by
    /// `OpenSession` for the session-credential ECDH chain.
    pub(crate) app_pub_key: [u8; P384_PUB_KEY_LEN],
    /// `true` once `EstablishCredential` has stored a credential into
    /// this partition. Cleared on `disable` and `free`.
    pub(crate) app_credential_set: bool,

    /// Vault key ID for the RSA-2k unwrapping key. Generated during
    /// `part_enable`, used by `GetUnwrappingKey` and `RsaUnwrap`.
    pub(crate) unwrapping_key_id: Option<HsmKeyId>,

    /// DER-encoded RSA-2k public key for unwrapping (SPKI format).
    unwrapping_pub_key: Vec<u8>,
}

impl Default for PartitionEntry {
    fn default() -> Self {
        Self {
            state: PartState::Unallocated,
            res_mask: 0,
            id: [0u8; PART_ID_LEN],
            id_key_id: None,
            id_pub_key: [0u8; P384_PUB_KEY_LEN],
            leaf_cert: [0u8; MAX_CERT_DER_LEN],
            leaf_cert_len: 0,
            session_table: SessionTable::new(),
            vault: KeyVault::new(0),
            establish_cred_key_id: None,
            establish_cred_pub_key: [0u8; P384_PUB_KEY_LEN],
            session_enc_key_id: None,
            session_enc_pub_key: [0u8; P384_PUB_KEY_LEN],
            nonce: [0u8; NONCE_LEN],
            sealed_bk3: [0u8; SEALED_BK3_SIZE],
            sealed_bk3_len: 0,
            masked_bk_boot: [0u8; MASKED_BK_BOOT_SIZE],
            masked_bk_boot_len: 0,
            app_user_id: [0u8; APP_ID_LEN],
            app_pin: [0u8; APP_PIN_LEN],
            app_pub_key: [0u8; P384_PUB_KEY_LEN],
            app_credential_set: false,
            unwrapping_key_id: None,
            unwrapping_pub_key: Vec::new(),
        }
    }
}

/// Table of all partition entries.
///
/// Stored in an [`UnsafeCell`] on [`StdHsmPal`] so that `&self` trait
/// methods can return borrowed slices into the entries.  The table is
/// heap-allocated (boxed) because `NUM_PARTITIONS × sizeof(PartitionEntry)`
/// exceeds 155 KB — too large for the stack during construction and
/// moves.
///
/// # Thread safety
///
/// Not `Sync` — the [`UnsafeCell`] wrapper on `StdHsmPal` prevents
/// sharing across threads.  All access occurs on the single-threaded
/// Embassy executor.
pub(crate) struct PartitionTable {
    /// Fixed array of partition entries indexed by `pid`.
    ///
    /// Boxed to avoid 155KB+ on the stack during construction and moves.
    pub(crate) entries: Box<[PartitionEntry; NUM_PARTITIONS]>,

    /// Global resource bitmask — union of all partitions' `res_mask` values.
    ///
    /// Used to detect double-allocation: a new partition's `res_mask` must
    /// not overlap with this value (`res_mask & global_res_mask == 0`).
    global_res_mask: u128,
}

impl Default for PartitionTable {
    fn default() -> Self {
        Self {
            entries: Box::new(core::array::from_fn(|_| PartitionEntry::default())),
            global_res_mask: 0,
        }
    }
}

/// A sideband command sent from [`StdHsm`] to the Embassy thread for
/// partition allocation or deallocation.
///
/// Each command carries a oneshot reply channel so the caller can
/// `await` the result.
///
/// [`StdHsm`]: azihsm_fw_hsm_std::StdHsm
pub enum PartCommand {
    /// Allocate a partition: generate a random ID and ECC-384 key pair,
    /// assign resources, and transition from `Disabled` to `Uninitialized`.
    Alloc {
        /// Partition index (must be < [`NUM_PARTITIONS`]).
        pid: u8,
        /// Resource bitmask — each set bit assigns one vault table to
        /// this partition.  Must not overlap with any already-allocated
        /// resource (checked against [`PartitionTable::global_res_mask`]).
        res_mask: u128,
        /// Oneshot channel for the allocation result.
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },

    /// Free a partition: zeroize all cryptographic material, release
    /// resources, and transition to `Unallocated`.
    Free {
        pid: u8,
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },

    /// Enable a partition: create internal ECC-384 key pairs and nonce.
    /// Transitions `Allocated | Disabled → Enabled`.
    Enable {
        pid: u8,
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },

    /// Disable a partition: clear internal keys, nonce, vault, sessions.
    /// Transitions `Enabled → Disabled`.
    Disable {
        pid: u8,
        reply: tokio::sync::oneshot::Sender<HsmResult<()>>,
    },
}

// ---------------------------------------------------------------------------
// HsmPartitionManager trait implementation (read-only, called by core)
// ---------------------------------------------------------------------------

impl HsmPartitionManager for StdHsmPal {
    /// Returns the current state of the partition at index `pid`.
    fn part_state(&self, pid: HsmPartId) -> HsmResult<PartState> {
        // SAFETY: Embassy is single-threaded. This synchronous method
        // completes without yielding, so no concurrent mutation occurs.
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        Ok(table.entries[idx].state)
    }

    /// Returns the resource count allocated to the partition at `pid`.
    fn part_res_count(&self, pid: HsmPartId) -> HsmResult<u8> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(entry.res_mask.count_ones() as u8)
    }

    /// Returns the 16-byte identity blob for the partition at `pid`.
    fn part_id(&self, pid: HsmPartId) -> HsmResult<PartId<'_>> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let entry = &table.entries[idx];
        if entry.state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&entry.id)
    }

    fn part_id_key_id(&self, pid: HsmPartId) -> HsmResult<HsmKeyId> {
        self.active_part(pid)?
            .id_key_id
            .ok_or(HsmError::InternalError)
    }

    fn part_id_pub_key(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.active_part(pid)?.id_pub_key, out)
    }

    fn part_establish_cred_key_id(&self, pid: HsmPartId) -> HsmResult<Option<HsmKeyId>> {
        Ok(self.enabled_part(u8::from(pid))?.establish_cred_key_id)
    }

    fn part_establish_cred_pub_key(
        &self,
        pid: HsmPartId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        copy_out(
            &self.enabled_part(u8::from(pid))?.establish_cred_pub_key,
            out,
        )
    }

    fn part_session_enc_key_id(&self, pid: HsmPartId) -> HsmResult<HsmKeyId> {
        self.enabled_part(u8::from(pid))?
            .session_enc_key_id
            .ok_or(HsmError::InternalError)
    }

    fn part_session_enc_pub_key(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.enabled_part(u8::from(pid))?.session_enc_pub_key, out)
    }

    fn part_clear_establish_cred_key(&self, pid: HsmPartId) -> HsmResult<()> {
        let entry = self.enabled_part_mut(u8::from(pid))?;
        if let Some(kid) = entry.establish_cred_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.establish_cred_pub_key.fill(0);
        Ok(())
    }

    fn part_nonce(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize> {
        copy_out(&self.enabled_part(u8::from(pid))?.nonce, out)
    }

    fn part_nonce_refresh(&self, pid: HsmPartId) -> HsmResult<()> {
        let entry = self.enabled_part_mut(u8::from(pid))?;
        Rng::rand_bytes(&mut entry.nonce).map_err(|_| HsmError::InternalError)
    }

    fn part_sealed_bk3(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.active_part(pid)?;
        if entry.sealed_bk3_len == 0 {
            return Err(HsmError::SealedBk3NotPresent);
        }
        let len = entry.sealed_bk3_len as usize;
        if let Some(buf) = out {
            if buf.len() < len {
                return Err(HsmError::InvalidArg);
            }
            buf[..len].copy_from_slice(&entry.sealed_bk3[..len]);
        }
        Ok(len)
    }

    fn part_set_sealed_bk3(&self, pid: HsmPartId, data: &[u8]) -> HsmResult<()> {
        if data.len() > SEALED_BK3_SIZE {
            return Err(HsmError::SealedBk3TooLarge);
        }
        let entry = self.active_part_mut(pid)?;
        if entry.sealed_bk3_len != 0 {
            return Err(HsmError::SealedBk3AlreadySet);
        }
        entry.sealed_bk3[..data.len()].copy_from_slice(data);
        entry.sealed_bk3_len = data.len() as u32;
        Ok(())
    }

    fn part_masked_bk_boot(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.active_part(pid)?;
        if entry.masked_bk_boot_len == 0 {
            // No DDI status code currently maps to "MaskedBkBoot not present";
            // KeyNotFound is the closest existing semantic.
            return Err(HsmError::KeyNotFound);
        }
        let len = entry.masked_bk_boot_len as usize;
        if let Some(buf) = out {
            if buf.len() < len {
                return Err(HsmError::InvalidArg);
            }
            buf[..len].copy_from_slice(&entry.masked_bk_boot[..len]);
        }
        Ok(len)
    }

    fn part_set_masked_bk_boot(&self, pid: HsmPartId, data: &[u8]) -> HsmResult<()> {
        if data.len() > MASKED_BK_BOOT_SIZE {
            return Err(HsmError::InvalidArg);
        }
        let entry = self.active_part_mut(pid)?;
        if entry.masked_bk_boot_len != 0 {
            return Err(HsmError::Bk3AlreadyInitialized);
        }
        entry.masked_bk_boot[..data.len()].copy_from_slice(data);
        entry.masked_bk_boot_len = data.len() as u32;
        Ok(())
    }

    fn part_user_credential(
        &self,
        pid: HsmPartId,
    ) -> HsmResult<(
        &[u8; APP_ID_LEN],
        &[u8; APP_PIN_LEN],
        &[u8; P384_PUB_KEY_LEN],
    )> {
        let entry = self.active_part(pid)?;
        if !entry.app_credential_set {
            return Err(HsmError::InvalidAppCredentials);
        }
        Ok((&entry.app_user_id, &entry.app_pin, &entry.app_pub_key))
    }

    fn part_set_user_credential(
        &self,
        pid: HsmPartId,
        id: &[u8; APP_ID_LEN],
        pin: &[u8; APP_PIN_LEN],
        pub_key: &[u8; P384_PUB_KEY_LEN],
    ) -> HsmResult<()> {
        let entry = self.active_part_mut(pid)?;
        if entry.app_credential_set {
            return Err(HsmError::VaultAppLimitReached);
        }
        entry.app_user_id = *id;
        entry.app_pin = *pin;
        entry.app_pub_key = *pub_key;
        entry.app_credential_set = true;
        Ok(())
    }

    fn part_unwrapping_key_id(&self, pid: HsmPartId) -> HsmResult<HsmKeyId> {
        self.enabled_part(u8::from(pid))?
            .unwrapping_key_id
            .ok_or(HsmError::KeyNotFound)
    }

    fn part_unwrapping_pub_key(&self, pid: HsmPartId, out: Option<&mut [u8]>) -> HsmResult<usize> {
        let entry = self.enabled_part(u8::from(pid))?;
        let der = &entry.unwrapping_pub_key;
        if der.is_empty() {
            return Err(HsmError::KeyNotFound);
        }
        if let Some(buf) = out {
            if buf.len() < der.len() {
                return Err(HsmError::InvalidArg);
            }
            buf[..der.len()].copy_from_slice(der);
        }
        Ok(der.len())
    }
}

// ---------------------------------------------------------------------------
// Shared partition access helpers (used by vault.rs, session.rs, etc.)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Borrow a partition entry that is not Unallocated.
    pub(crate) fn active_part(&self, pid: HsmPartId) -> HsmResult<&PartitionEntry> {
        let table = unsafe { &*self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&table.entries[idx])
    }

    /// Borrow a partition entry that is not Unallocated (mutable).
    #[allow(clippy::mut_from_ref)]
    pub(crate) fn active_part_mut(&self, pid: HsmPartId) -> HsmResult<&mut PartitionEntry> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = u8::from(pid) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut table.entries[idx])
    }

    /// Borrow a partition that is in Enabled state.
    fn enabled_part(&self, pid: u8) -> HsmResult<&PartitionEntry> {
        let table = unsafe { &*self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&table.entries[idx])
    }

    /// Borrow a partition that is in Enabled state (mutable).
    #[allow(clippy::mut_from_ref)]
    fn enabled_part_mut(&self, pid: u8) -> HsmResult<&mut PartitionEntry> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(&mut table.entries[idx])
    }
}

/// Copy `data` into `out` if provided, return length.
fn copy_out(data: &[u8], out: Option<&mut [u8]>) -> HsmResult<usize> {
    if let Some(buf) = out {
        if buf.len() < data.len() {
            return Err(HsmError::NotEnoughSpace);
        }
        buf[..data.len()].copy_from_slice(data);
    }
    Ok(data.len())
}

// ---------------------------------------------------------------------------
// Internal partition lifecycle (called by part_cmd_task on Embassy thread)
// ---------------------------------------------------------------------------

impl StdHsmPal {
    /// Allocate a partition: generate identity and ECC-384 key pair.
    ///
    /// Transitions `Unallocated → Allocated`.
    pub async fn part_alloc_internal(&self, pid: u8, res_mask: u128) -> HsmResult<()> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }

        // Validate before mutating anything.
        let valid_bits: u128 = (1u128 << MAX_RESOURCES) - 1;
        if res_mask & !valid_bits != 0 {
            return Err(HsmError::InvalidArg);
        }
        if res_mask & table.global_res_mask != 0 {
            return Err(HsmError::NotEnoughSpace);
        }

        // Generate identity outside the table borrow — no partial state on failure.
        let mut id = [0u8; PART_ID_LEN];
        Rng::rand_bytes(&mut id).map_err(|_| HsmError::InternalError)?;

        // Reserve resources + create vault so keygen has somewhere to store.
        let entry = &mut table.entries[idx];
        entry.res_mask = res_mask;
        entry.vault = KeyVault::new(res_mask.count_ones() as usize);
        table.global_res_mask |= res_mask;

        // Generate identity ECC P-384 key pair.
        let id_attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_sign(true);
        let mut id_pub = [0u8; P384_PUB_KEY_LEN];
        let id_result = self
            .create_internal_ecc384_key(
                idx as u8,
                HsmVaultKeyKind::Ecc384Private,
                id_attrs,
                HsmEccPct::SignVerify,
                &mut id_pub,
            )
            .await;

        // Commit or rollback.
        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[idx];
        match id_result {
            Ok(id_kid) => {
                entry.id = id;
                entry.id_key_id = Some(id_kid);
                entry.id_pub_key = id_pub;
                entry.state = PartState::Allocated;
            }
            Err(e) => {
                // Rollback: release resources.
                table.global_res_mask &= !res_mask;
                entry.res_mask = 0;
                entry.vault = KeyVault::new(0);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Enable a partition: create internal ECC-384 key pairs and nonce.
    ///
    /// Transitions `Allocated | Disabled → Enabled`.
    pub async fn part_enable_internal(&self, pid: u8) -> HsmResult<()> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        let state = table.entries[idx].state;
        if state != PartState::Allocated && state != PartState::Disabled {
            return Err(HsmError::InvalidArg);
        }

        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_derive(true);

        // Generate establish-credential encryption ECC-384 key pair.
        let mut ec_pub = [0u8; P384_PUB_KEY_LEN];
        let ec_kid = self
            .create_internal_ecc384_key(
                pid,
                HsmVaultKeyKind::EstablishCred,
                attrs,
                HsmEccPct::KeyAgreement,
                &mut ec_pub,
            )
            .await?;

        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[idx];
        entry.establish_cred_key_id = Some(ec_kid);
        entry.establish_cred_pub_key = ec_pub;

        // Generate session encryption ECC-384 key pair.
        let mut se_pub = [0u8; P384_PUB_KEY_LEN];
        let se_result = self
            .create_internal_ecc384_key(
                pid,
                HsmVaultKeyKind::SessionEncryption,
                attrs,
                HsmEccPct::KeyAgreement,
                &mut se_pub,
            )
            .await;

        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[idx];
        match se_result {
            Ok(se_kid) => {
                entry.session_enc_key_id = Some(se_kid);
                entry.session_enc_pub_key = se_pub;
            }
            Err(e) => {
                let _ = entry.vault.delete(ec_kid);
                entry.establish_cred_key_id = None;
                entry.establish_cred_pub_key.fill(0);
                return Err(e);
            }
        }

        // Generate 32-byte random nonce.
        if Rng::rand_bytes(&mut entry.nonce).is_err() {
            // Rollback both keys.
            Self::clear_enabled_state(entry);
            return Err(HsmError::InternalError);
        }

        // Generate RSA-2k unwrapping key pair.
        let (rsa_priv, rsa_pub) = self.rsa.gen_keypair(2048).await.map_err(|e| {
            Self::clear_enabled_state(entry);
            e
        })?;
        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[idx];

        let priv_der_len = rsa_priv
            .to_bytes(None)
            .map_err(|_| HsmError::InternalError)?;
        let mut priv_der = vec![0u8; priv_der_len];
        rsa_priv
            .to_bytes(Some(&mut priv_der))
            .map_err(|_| HsmError::InternalError)?;

        // Extract raw LE pub key: N_LE (256 bytes) || E_LE (4 bytes)
        // for the wire format expected by pub_key_der_post_decode.
        let n_len = rsa_pub.n(None).map_err(|_| HsmError::InternalError)?;
        let mut n_be = vec![0u8; n_len];
        rsa_pub
            .n(Some(&mut n_be))
            .map_err(|_| HsmError::InternalError)?;
        let e_len = rsa_pub.e(None).map_err(|_| HsmError::InternalError)?;
        let mut e_be = vec![0u8; e_len];
        rsa_pub
            .e(Some(&mut e_be))
            .map_err(|_| HsmError::InternalError)?;
        // Pad e to 4 bytes (BE) then reverse.
        let mut e_4 = [0u8; 4];
        let e_off = 4 - e_be.len().min(4);
        e_4[e_off..].copy_from_slice(&e_be[..e_be.len().min(4)]);
        // Build raw LE: N_LE || E_LE.
        let mut raw_le = vec![0u8; n_len + 4];
        for i in 0..n_len {
            raw_le[i] = n_be[n_len - 1 - i];
        }
        for i in 0..4 {
            raw_le[n_len + i] = e_4[3 - i];
        }

        let rsa_attrs = HsmVaultKeyAttrs::new()
            .with_unwrap(true)
            .with_internal(true)
            .with_local(true);
        match entry.vault.create(
            &priv_der,
            HsmVaultKeyKind::Rsa2kPrivate,
            None,
            rsa_attrs,
            &[],
        ) {
            Ok(kid) => {
                entry.unwrapping_key_id = Some(kid);
                entry.unwrapping_pub_key = raw_le;
            }
            Err(e) => {
                Self::clear_enabled_state(entry);
                return Err(e);
            }
        }

        entry.state = PartState::Enabled;
        Ok(())
    }

    /// Disable a partition: clear internal keys, nonce, vault, sessions.
    ///
    /// Transitions `Enabled → Disabled`.
    pub fn part_disable_internal(&self, pid: u8) -> HsmResult<()> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state != PartState::Enabled {
            return Err(HsmError::InvalidArg);
        }

        Self::clear_enabled_state(&mut table.entries[idx]);
        table.entries[idx].state = PartState::Disabled;
        Ok(())
    }

    /// Free a partition: zeroize all material and release resources.
    ///
    /// Accepts `Allocated | Enabled | Disabled → Unallocated`.
    /// If `Enabled`, implicitly clears internal keys first.
    pub fn part_free_internal(&self, pid: u8) -> HsmResult<()> {
        let table = unsafe { &mut *self.part_table.get() };
        let idx = pid as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        if table.entries[idx].state == PartState::Unallocated {
            return Err(HsmError::InvalidArg);
        }

        let entry = &mut table.entries[idx];

        // If enabled, clear internal keys/nonce/vault/sessions first.
        if entry.state == PartState::Enabled {
            Self::clear_enabled_state(entry);
        }

        // Zeroize identity material.
        entry.id.fill(0);
        if let Some(kid) = entry.id_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.id_pub_key.fill(0);
        entry.leaf_cert[..entry.leaf_cert_len].fill(0);
        entry.leaf_cert_len = 0;

        // Zeroize sealed BK3 (preserved across enable/disable, but not
        // across full free).
        entry.sealed_bk3.fill(0);
        entry.sealed_bk3_len = 0;

        // Zeroize masked BK_BOOT (also part of provisioned state).
        entry.masked_bk_boot.fill(0);
        entry.masked_bk_boot_len = 0;

        // Release resources.
        table.global_res_mask &= !entry.res_mask;
        entry.res_mask = 0;
        entry.vault = KeyVault::new(0);
        entry.state = PartState::Unallocated;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Generate an ECC P-384 key pair via [`HsmEcc::ecc_gen_keypair`],
    /// store the private key DER in the vault, and write raw public key
    /// coordinates (x ∥ y) into `pub_key_out`.
    ///
    /// Returns the vault key ID.
    async fn create_internal_ecc384_key(
        &self,
        pid: u8,
        kind: HsmVaultKeyKind,
        attrs: HsmVaultKeyAttrs,
        pct: HsmEccPct,
        pub_key_out: &mut [u8; P384_PUB_KEY_LEN],
    ) -> HsmResult<HsmKeyId> {
        let priv_max = HsmEccCurve::P384.priv_key_der_max();
        let mut priv_buf = vec![0u8; priv_max];

        let priv_len = self
            .ecc_gen_keypair(HsmEccCurve::P384, Some(&mut priv_buf), pub_key_out, pct)
            .await?;

        // Store private key DER in vault.
        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[pid as usize];
        entry
            .vault
            .create(&priv_buf[..priv_len], kind, None, attrs, &[])
    }

    /// Clear all state associated with an enabled partition (internal keys,
    /// nonce, vault keys, sessions).  Does NOT change the state field.
    fn clear_enabled_state(entry: &mut PartitionEntry) {
        if let Some(kid) = entry.establish_cred_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.establish_cred_pub_key.fill(0);

        if let Some(kid) = entry.session_enc_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.session_enc_pub_key.fill(0);

        entry.nonce.fill(0);
        entry.vault.clear();
        entry.session_table = SessionTable::new();

        // Clear any user credential. mcr-hsm semantics: per-partition
        // credential is reset whenever the partition is disabled, since
        // OpenSession can re-establish a fresh one. This does NOT touch
        // sealed_bk3 / masked_bk_boot which survive disable/enable.
        entry.app_user_id.fill(0);
        entry.app_pin.fill(0);
        entry.app_pub_key.fill(0);
        entry.app_credential_set = false;

        // Unwrapping key is cleared on disable — regenerated on re-enable.
        if let Some(kid) = entry.unwrapping_key_id.take() {
            let _ = entry.vault.delete(kid);
        }
        entry.unwrapping_pub_key.clear();
    }
}

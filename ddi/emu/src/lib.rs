// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! DDI Implementation - Azure Integrated HSM Emulator.
//!
//! This crate bridges the host-side AZIHSM SDK (`azihsm_ddi_interface`) to
//! the in-process firmware running on the standard platform abstraction
//! layer (`azihsm_fw_hsm_std::StdHsm`). It is intended for development and
//! testing the host SDK against the new firmware codebase without
//! requiring real hardware.
//!
//! # Scope
//!
//! At the time of writing, the firmware DDI dispatcher implements only a
//! handful of commands ([`DdiOp::GetApiRev`], [`DdiOp::GetDeviceInfo`],
//! [`DdiOp::GetCertChainInfo`], [`DdiOp::GetCertificate`],
//! [`DdiOp::ShaDigest`]). Other commands return `UnsupportedCmd`. The
//! fast-path AES (GCM/XTS) and `simulate_nssr_after_lm` interfaces have
//! no equivalent in the new firmware and always return
//! [`DdiStatus::UnsupportedCmd`].
//!
//! [`DdiOp::GetApiRev`]: azihsm_ddi_types::DdiOp::GetApiRev
//! [`DdiOp::GetDeviceInfo`]: azihsm_ddi_types::DdiOp::GetDeviceInfo
//! [`DdiOp::GetCertChainInfo`]: azihsm_ddi_types::DdiOp::GetCertChainInfo
//! [`DdiOp::GetCertificate`]: azihsm_ddi_types::DdiOp::GetCertificate
//! [`DdiOp::ShaDigest`]: azihsm_ddi_types::DdiOp::ShaDigest
//! [`DdiStatus::UnsupportedCmd`]: azihsm_ddi_types::DdiStatus::UnsupportedCmd

mod ddi;
mod dev;

pub use ddi::DdiEmu;
pub use dev::DdiEmuDev;
pub use dev::EMU_DEVICE_PATH;

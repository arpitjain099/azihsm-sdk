// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Establish-credential round-trip integration tests.
//!
//! Exercises the full host-side flow up to and including
//! [`DdiOp::EstablishCredential`] without proceeding to
//! `OpenSession` (which lands in a later iteration). Used to verify
//! that the iter-5 `EstablishCredential` dispatcher works end-to-end:
//! POTA signature verify → ECDH → HKDF → AES-CBC + HMAC-verify →
//! credential storage.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

/// No-op setup. The full credential flow is exercised inside the test
/// closure itself.
pub fn setup(_dev: &mut <DdiTest as Ddi>::Dev, _ddi: &DdiTest, _path: &str) -> u16 {
    0
}

/// No-op cleanup. Each test runs in its own nextest process so the
/// global HSM state is fresh.
pub fn cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    _ddi: &DdiTest,
    _path: &str,
    _setup_session_id: Option<u16>,
) {
}

#[test]
fn test_establish_credential_succeeds() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _incorrect_session_id| {
        let result = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(
            result.is_ok(),
            "EstablishCredential round-trip must succeed: {:?}",
            result
        );
    });
}

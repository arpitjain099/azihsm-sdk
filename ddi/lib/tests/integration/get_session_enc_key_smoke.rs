// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GetSessionEncryptionKey smoke tests for the emu backend.
//!
//! Exercises the full credential-establishment chain then calls
//! `GetSessionEncryptionKey` to verify the session-encryption public
//! key and nonce are returned successfully.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(_dev: &mut <DdiTest as Ddi>::Dev, _ddi: &DdiTest, _path: &str) -> u16 {
    0
}

pub fn cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    _ddi: &DdiTest,
    _path: &str,
    _setup_session_id: Option<u16>,
) {
}

#[test]
fn test_get_session_encryption_key_succeeds() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Establish credential first.
        let result = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(
            result.is_ok(),
            "EstablishCredential must succeed: {:?}",
            result
        );

        // Now get the session encryption key.
        let resp =
            helper_get_session_encryption_key(dev, None, Some(DdiApiRev { major: 1, minor: 0 }));
        assert!(
            resp.is_ok(),
            "GetSessionEncryptionKey must succeed: {:?}",
            resp
        );
    });
}

#[test]
fn test_get_session_encryption_key_with_session_id_rejected() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let result = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(result.is_ok());

        // Passing a session_id should fail — this is a NoSession command.
        let resp = helper_get_session_encryption_key(dev, Some(10), None);
        assert!(resp.is_err(), "Should reject session_id: {:?}", resp);
    });
}

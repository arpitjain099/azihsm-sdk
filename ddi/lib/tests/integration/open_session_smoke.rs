// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSession smoke tests for the emu backend.
//!
//! Exercises the full credential-establishment + open-session chain:
//! EstablishCredential → GetSessionEncryptionKey → OpenSession.

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
fn test_open_session_succeeds() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // 1. Establish credential.
        let result = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(
            result.is_ok(),
            "EstablishCredential must succeed: {:?}",
            result
        );

        // 2. Encrypt credential for open session.
        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        // 3. Open session.
        let resp = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        assert!(resp.is_ok(), "OpenSession must succeed: {:?}", resp);

        let resp = resp.unwrap();
        assert!(resp.hdr.sess_id.is_some(), "Response must include sess_id");
    });
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CloseSession smoke tests for the emu backend.
//!
//! Exercises the full session lifecycle:
//! EstablishCredential → OpenSession → CloseSession.

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
fn test_close_session_succeeds() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // 1. Establish credential.
        let result = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(result.is_ok(), "EstablishCredential failed: {:?}", result);

        // 2. Open session.
        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );
        let open_resp = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        assert!(open_resp.is_ok(), "OpenSession failed: {:?}", open_resp);
        let sess_id = open_resp.unwrap().hdr.sess_id.unwrap();

        // 3. Close session.
        let close_resp =
            helper_close_session(dev, Some(sess_id), Some(DdiApiRev { major: 1, minor: 0 }));
        assert!(close_resp.is_ok(), "CloseSession failed: {:?}", close_resp);
    });
}

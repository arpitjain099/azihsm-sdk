// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! InitBk3 smoke tests for the emu backend.

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
fn test_init_bk3_succeeds() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let resp = helper_init_bk3(dev, HARD_CODED_BK3.to_vec()).unwrap();
        assert_eq!(resp.hdr.op, DdiOp::InitBk3);
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        assert!(!resp.data.masked_bk3.as_slice().is_empty());
        assert_eq!(resp.data.vm_launch_guid, [0u8; 16]);
    });
}

#[test]
fn test_init_bk3_twice_fails() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let first = helper_init_bk3(dev, HARD_CODED_BK3.to_vec()).unwrap();
        assert_eq!(first.hdr.status, DdiStatus::Success);

        let err = helper_init_bk3(dev, HARD_CODED_BK3.to_vec()).unwrap_err();
        assert!(matches!(
            err,
            DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)
        ));
    });
}

#[test]
fn test_init_bk3_then_set_get_sealed_bk3() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let init = helper_init_bk3(dev, HARD_CODED_BK3.to_vec()).unwrap();
        let masked_bk3 = init.data.masked_bk3.as_slice().to_vec();

        let set_resp = helper_set_sealed_bk3(dev, masked_bk3.clone()).unwrap();
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);

        let get_resp = helper_get_sealed_bk3(dev).unwrap();
        assert_eq!(get_resp.hdr.op, DdiOp::GetSealedBk3);
        assert_eq!(get_resp.data.sealed_bk3.as_slice(), masked_bk3.as_slice());
    });
}

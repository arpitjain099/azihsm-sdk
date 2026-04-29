// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end smoke tests for `azihsm_ddi_emu`.
//!
//! Drive the trait surface (`Ddi` / `DdiDev`) the way a real consumer
//! would, and check that DDI requests reach the in-process firmware and
//! come back with sane data.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_ddi_emu::DdiEmu;
use azihsm_ddi_emu::EMU_DEVICE_PATH;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::DdiApiRev;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiGetApiRevCmdReq;
use azihsm_ddi_types::DdiGetApiRevReq;
use azihsm_ddi_types::DdiGetEstablishCredEncryptionKeyCmdReq;
use azihsm_ddi_types::DdiGetEstablishCredEncryptionKeyReq;
use azihsm_ddi_types::DdiHashAlgorithm;
use azihsm_ddi_types::DdiOp;
use azihsm_ddi_types::DdiReqHdr;
use azihsm_ddi_types::DdiShaDigestCmdReq;
use azihsm_ddi_types::DdiShaDigestReq;

#[test]
fn dev_info_list_returns_emu_device() {
    let ddi = DdiEmu::default();
    let devs = ddi.dev_info_list();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].path, EMU_DEVICE_PATH);
}

#[test]
fn open_unknown_path_fails() {
    let ddi = DdiEmu::default();
    let res = ddi.open_dev("/dev/nonexistent");
    assert!(res.is_err(), "opening unknown path must fail");
}

#[test]
fn get_api_rev_round_trips_through_emulator() {
    let ddi = DdiEmu::default();
    let mut dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");
    dev.set_device_kind(DdiDeviceKind::Virtual);

    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    let resp = dev
        .exec_op(&req, &mut cookie)
        .expect("GetApiRev should succeed against the emulator");

    assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
    assert_eq!(
        resp.data.min,
        DdiApiRev { major: 1, minor: 0 },
        "firmware should report min api rev 1.0",
    );
    assert_eq!(
        resp.data.max,
        DdiApiRev { major: 1, minor: 0 },
        "firmware should report max api rev 1.0",
    );
}

/// Round-trip a SHA-256 digest through the firmware. This regresses two
/// things at once:
///
/// 1. SQE `session_ctrl` for `ShaDigest` must encode `NoSession` (0). The
///    host SDK historically omitted `ShaDigest` from its NoSession set,
///    which made the firmware reject the IO.
/// 2. The firmware's ShaDigest dispatcher actually computes the right
///    digest for the canonical NIST FIPS-180-2 "abc" test vector.
#[test]
fn sha256_digest_round_trips_through_emulator() {
    let ddi = DdiEmu::default();
    let mut dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");
    dev.set_device_kind(DdiDeviceKind::Virtual);

    let msg = b"abc";
    let req = DdiShaDigestCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::ShaDigest,
            sess_id: None,
        },
        data: DdiShaDigestReq {
            sha_mode: DdiHashAlgorithm::Sha256,
            msg: MborByteArray::from_slice(msg).expect("input fits in 1024 bytes"),
        },
        ext: None,
    };

    let mut cookie = None;
    let resp = dev
        .exec_op(&req, &mut cookie)
        .expect("ShaDigest should succeed against the emulator");

    assert_eq!(resp.hdr.op, DdiOp::ShaDigest);
    // FIPS-180-2 §B.1 — SHA-256 of "abc"
    let expected = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22,
        0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00,
        0x15, 0xAD,
    ];
    assert_eq!(
        resp.data.digest.as_slice(),
        &expected[..],
        "SHA-256(\"abc\") mismatch",
    );
}

/// Round-trip [`DdiOp::GetEstablishCredEncryptionKey`] through the
/// emulator and parse the response with [`DeviceCredKey::new`].
///
/// `DeviceCredKey::new` calls `EccPublicKey::from_bytes` on the returned
/// `pub_key.der` field, which only succeeds if the bytes are valid DER.
/// Firmware emits raw PKA-native (little-endian) coordinates, and the
/// host SDK's `pub_key_der_post_decode` hook reverses each half back to
/// big-endian and assembles DER on the way in — but only when the dev
/// handle is told the device is `Physical`. This test pins the
/// end-to-end contract and is the regression guard for the iter-2 fix.
#[test]
fn get_establish_cred_encryption_key_round_trips_through_emulator() {
    let ddi = DdiEmu::default();
    let mut dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");
    // Firmware advertises Physical via `GetDeviceInfo` — match it so
    // that `MborDecoder` runs the `post_decode_fn` hooks that convert
    // the wire-format raw key into DER for the host SDK.
    dev.set_device_kind(DdiDeviceKind::Physical);

    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id: None,
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };

    let mut cookie = None;
    let resp = dev
        .exec_op(&req, &mut cookie)
        .expect("GetEstablishCredEncryptionKey should succeed");

    assert_eq!(resp.hdr.op, DdiOp::GetEstablishCredEncryptionKey);
    assert_eq!(resp.data.nonce.len(), 32);

    // The actual regression guard: parse the returned key as DER. This
    // is the line that previously panicked with `EccKeyImportError`.
    let _key = DeviceCredKey::new(&resp.data.pub_key, resp.data.nonce)
        .expect("DeviceCredKey::new must accept the DER-converted public key");
}

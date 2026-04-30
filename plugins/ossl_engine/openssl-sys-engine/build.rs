// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for openssl-sys-engine.
//!
//! Discovers OpenSSL 1.1.x via pkg-config, verifies the version, and runs
//! bindgen to generate Rust FFI bindings from `wrapper.h`.

use std::env;
use std::path::PathBuf;

fn main() {
    // Discover OpenSSL via pkg-config.
    let lib = pkg_config::Config::new()
        .atleast_version("1.1.0")
        .probe("libcrypto")
        .expect(
            "Could not find libcrypto via pkg-config. \
             Set PKG_CONFIG_PATH to an OpenSSL 1.1.x installation.",
        );

    // Reject anything other than OpenSSL 1.x -- the engine targets 1.1.x only.
    let major: u32 = lib
        .version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("Could not parse OpenSSL version: {}", lib.version));

    if major != 1 {
        panic!(
            "Found OpenSSL {} but this engine requires 1.1.x. \
             For OpenSSL 3.x, use the provider at plugins/ossl_prov instead.",
            lib.version
        );
    }

    // Link directives (pkg-config emits these, but be explicit).
    println!("cargo::rustc-link-lib=crypto");
    for path in &lib.link_paths {
        println!("cargo::rustc-link-search=native={}", path.display());
    }

    // Run bindgen.
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // ENGINE API
        .allowlist_function("ENGINE_.*")
        // EVP (keys, ciphers, digests)
        .allowlist_function("EVP_.*")
        // RSA method construction
        .allowlist_function("RSA_meth_.*")
        .allowlist_function("RSA_get_ex_data")
        .allowlist_function("RSA_set_ex_data")
        .allowlist_function("RSA_get_ex_new_index")
        // EC method construction
        .allowlist_function("EC_KEY_METHOD_.*")
        .allowlist_function("EC_KEY_.*")
        .allowlist_function("EC_POINT_.*")
        .allowlist_function("EC_GROUP_.*")
        // Error reporting
        .allowlist_function("ERR_put_error")
        .allowlist_function("ERR_add_error_data")
        // Crypto utilities
        .allowlist_function("CRYPTO_get_ex_new_index")
        .allowlist_function("CRYPTO_set_mem_functions")
        .allowlist_function("OPENSSL_init_crypto")
        // Types
        .allowlist_type("ENGINE")
        .allowlist_type("EVP_PKEY")
        .allowlist_type("EVP_PKEY_CTX")
        .allowlist_type("EVP_MD")
        .allowlist_type("EVP_CIPHER")
        .allowlist_type("RSA")
        .allowlist_type("RSA_METHOD")
        .allowlist_type("EC_KEY")
        .allowlist_type("EC_KEY_METHOD")
        .allowlist_type("UI_METHOD")
        .allowlist_type("ECDSA_SIG")
        .allowlist_type("BIGNUM")
        .allowlist_type("dynamic_fns")
        .allowlist_type("dynamic_MEM_fns")
        // Constants
        .allowlist_var("OSSL_DYNAMIC_.*")
        .allowlist_var("NID_.*")
        .allowlist_var("EVP_PKEY_.*")
        .allowlist_var("ERR_LIB_ENGINE")
        .allowlist_var("ERR_R_.*")
        .allowlist_var("CRYPTO_EX_INDEX_ENGINE")
        .allowlist_var("CRYPTO_EX_INDEX_RSA")
        .allowlist_var("CRYPTO_EX_INDEX_EC_KEY")
        .allowlist_var("OPENSSL_INIT_NO_ATEXIT")
        .allowlist_var("ENGINE_CMD_FLAG_.*")
        // Layout tests are fragile across minor OpenSSL versions.
        .layout_tests(false);

    for path in &lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder.generate().expect("bindgen failed");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

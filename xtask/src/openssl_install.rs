// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Helper to resolve OpenSSL installations, building from source if necessary.

#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use anyhow::Context as _;
#[cfg(target_os = "linux")]
use xshell::cmd;
#[cfg(target_os = "linux")]
use xshell::Shell;

#[cfg(target_os = "linux")]
const OPENSSL_3_VERSION: &str = "3.0.3";
#[cfg(target_os = "linux")]
const OPENSSL_3_SHA256: &str = "ee0078adcef1de5f003c62c80cc96527721609c6f3bb42b7795df31f8b558c0b";
#[cfg(target_os = "linux")]
const OPENSSL_3_URL_TAG: &str = "openssl-3.0.3";

#[cfg(target_os = "linux")]
const OPENSSL_1_1_VERSION: &str = "1.1.1w";
#[cfg(target_os = "linux")]
const OPENSSL_1_1_SHA256: &str =
    "cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8";
#[cfg(target_os = "linux")]
const OPENSSL_1_1_URL_TAG: &str = "OpenSSL_1_1_1w";

#[cfg(target_os = "linux")]
fn target_dir() -> anyhow::Result<PathBuf> {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => Ok(std::env::current_dir()?.join("target")),
    }
}

#[cfg(target_os = "linux")]
fn install_dir_for(version: &str) -> anyhow::Result<PathBuf> {
    Ok(target_dir()?.join(format!("openssl-{version}")))
}

/// Checks whether the OpenSSL 3.x installation is available.
#[cfg(target_os = "linux")]
pub fn check_openssl() -> anyhow::Result<PathBuf> {
    match std::env::var("OPENSSL_DIR") {
        Ok(val) if val.trim().is_empty() => {
            anyhow::bail!(
                "OPENSSL_DIR is set but empty. \
                 Set it to an OpenSSL 3.x installation prefix."
            );
        }
        Ok(ref val) if !std::path::Path::new(val).is_dir() => {
            anyhow::bail!("OPENSSL_DIR={val:?} does not point to an existing directory.");
        }
        Ok(val) => {
            log::info!("using OPENSSL_DIR={val}");
            return Ok(PathBuf::from(val));
        }
        Err(_) => {}
    }

    let dir = install_dir_for(OPENSSL_3_VERSION)?;
    if dir.is_dir() {
        log::info!("using cached OpenSSL at {}", dir.display());
        return Ok(dir);
    }

    anyhow::bail!(
        "OpenSSL installation not found. \
         Run 'cargo xtask setup' first, or set OPENSSL_DIR to an existing OpenSSL 3.x prefix."
    );
}

/// Downloads, verifies, and builds an OpenSSL release from source.
#[cfg(target_os = "linux")]
fn build_openssl(
    version: &str,
    url_tag: &str,
    sha256: &str,
    configure_cmd: &str,
) -> anyhow::Result<PathBuf> {
    let install_dir = install_dir_for(version)?;
    if install_dir.is_dir() {
        log::info!("using cached OpenSSL {version} at {}", install_dir.display());
        return Ok(install_dir);
    }

    log::info!("building OpenSSL {version} into {}", install_dir.display());

    let sh = Shell::new()?;
    for tool in ["curl", "sha256sum", "make", "cc", "perl"] {
        if cmd!(sh, "which {tool}").quiet().run().is_err() {
            anyhow::bail!(
                "required tool `{tool}` not found. \
                 Install build prerequisites: sudo apt-get install build-essential coreutils curl perl"
            );
        }
    }

    let url = format!(
        "https://github.com/openssl/openssl/releases/download/{url_tag}/openssl-{version}.tar.gz"
    );
    let tarball = format!("/tmp/openssl-{version}.tar.gz");
    let src_dir = format!("/tmp/openssl-{version}");

    log::info!("downloading OpenSSL {version}...");
    cmd!(sh, "curl -fsSL -o {tarball} {url}").run()?;

    let checksum_output = cmd!(sh, "sha256sum {tarball}").read()?;
    let actual_hash = checksum_output
        .split_whitespace()
        .next()
        .context("failed to parse sha256sum output")?;
    anyhow::ensure!(
        actual_hash == sha256,
        "SHA-256 mismatch for {tarball}: expected {sha256}, got {actual_hash}"
    );

    cmd!(sh, "rm -rf {src_dir}").run()?;
    cmd!(sh, "tar xz -C /tmp -f {tarball}").run()?;

    sh.change_dir(&src_dir);
    cmd!(sh, "{configure_cmd} --prefix={install_dir} --libdir=lib").run()?;

    let nproc = cmd!(sh, "nproc").read()?;
    let nproc = nproc.trim();
    cmd!(sh, "make -j{nproc}").run()?;
    cmd!(sh, "make install_sw").run()?;

    log::info!("OpenSSL {version} installed to {}", install_dir.display());
    Ok(install_dir)
}

/// Resolves the OpenSSL 3.x installation, building from source if necessary.
#[cfg(target_os = "linux")]
pub fn ensure_openssl() -> anyhow::Result<PathBuf> {
    if std::env::var("OPENSSL_DIR").is_ok() {
        return check_openssl();
    }

    if let Ok(path) = check_openssl() {
        return Ok(path);
    }

    build_openssl(
        OPENSSL_3_VERSION,
        OPENSSL_3_URL_TAG,
        OPENSSL_3_SHA256,
        "./Configure",
    )
}

/// Resolves the OpenSSL 1.1.x installation, building from source if necessary.
///
/// Used by the OpenSSL ENGINE crates which target 1.1.x.
#[cfg(target_os = "linux")]
pub fn ensure_openssl_1_1() -> anyhow::Result<PathBuf> {
    build_openssl(
        OPENSSL_1_1_VERSION,
        OPENSSL_1_1_URL_TAG,
        OPENSSL_1_1_SHA256,
        "./config",
    )
}

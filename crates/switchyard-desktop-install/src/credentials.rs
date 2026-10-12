// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Server credentials belong to one installed config and remain separate from model-list keys.

use std::{path::Path, process::Command};

fn variables(config: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    let text = std::fs::read_to_string(config)
        .map_err(|_| "Could not read server credential references.")?;
    switchyard_runner::api_key_variables(&text).map_err(|e| e.to_string())
}

pub(crate) fn needs_saved(config: &Path) -> Result<bool, String> {
    Ok(variables(config)?
        .iter()
        .any(|name| std::env::var_os(name).is_none()))
}

// Candidate files use the original config's scope; JSON keeps path/name pairs unambiguous.
fn account(scope: &Path, variable: &str) -> Result<String, String> {
    let scope = match std::fs::canonicalize(scope) {
        Ok(scope) => scope,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = scope
                .parent()
                .ok_or("The server config must have a parent directory.")?;
            std::fs::canonicalize(parent)
                .map_err(|_| "Could not resolve the server config directory.")?
                .join(
                    scope
                        .file_name()
                        .ok_or("The server config must have a file name.")?,
                )
        }
        Err(_) => return Err("Could not resolve the installed server config.".into()),
    };
    let scope = scope
        .to_str()
        .ok_or("The server config path must be UTF-8.")?;
    serde_json::to_string(&(scope, variable)).map_err(|e| e.to_string())
}

fn same_variable(name: &std::ffi::OsStr, variable: &str) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
        let name: Vec<_> = name.encode_wide().collect();
        let variable: Vec<_> = variable.encode_utf16().collect();
        let (Ok(name_length), Ok(variable_length)) =
            (name.len().try_into(), variable.len().try_into())
        else {
            return false;
        };
        unsafe {
            CompareStringOrdinal(
                name.as_ptr(),
                name_length,
                variable.as_ptr(),
                variable_length,
                1,
            ) == CSTR_EQUAL
        }
    }
    #[cfg(not(windows))]
    {
        name == std::ffi::OsStr::new(variable)
    }
}

/// This function adds saved credentials only for absent variables.
/// Explicit values and removals remain authoritative, including empty or invalid values.
pub fn configure(command: &mut Command, config: &Path, scope: &Path) -> Result<(), String> {
    resolve(
        command,
        config,
        |name| std::env::var_os(name).is_some(),
        |name| read(&account(scope, name)?),
    )
}

/// The helper validates a candidate using credentials scoped to its original config.
/// It saves credentials only after the real server's dry-run succeeds.
pub fn validate(server: &Path, config: &Path, scope: &Path, save: bool) -> Result<(), String> {
    let mut validator = Command::new(server);
    configure(&mut validator, config, scope)?;
    let output = validator
        .arg("--config")
        .arg(config)
        .arg("--dry-run")
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout).into_owned()
        } else {
            stderr.into_owned()
        });
    }
    if save {
        capture(config, scope)?;
    }
    Ok(())
}

fn resolve(
    command: &mut Command,
    config: &Path,
    present: impl Fn(&str) -> bool,
    saved: impl Fn(&str) -> Result<Option<String>, String>,
) -> Result<(), String> {
    for variable in variables(config)? {
        if !command
            .get_envs()
            .any(|(name, _)| same_variable(name, &variable))
            && !present(&variable)
            && let Some(key) = saved(&variable)?
        {
            command.env(variable, key);
        }
    }
    Ok(())
}

/// This function captures declared shell credentials after the real server accepts the config.
pub(crate) fn capture(config: &Path, scope: &Path) -> Result<(), String> {
    #[cfg(any(target_os = "macos", windows))]
    for variable in variables(config)? {
        let account = account(scope, &variable)?;
        let key = match std::env::var(&variable) {
            Ok(key) => Some(key),
            Err(std::env::VarError::NotPresent) => read(&account)?,
            Err(std::env::VarError::NotUnicode(_)) => None,
        };
        if let Some(key) = key.filter(|key| !key.trim().is_empty()) {
            write(&account, &key)?;
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = (config, scope);
    Ok(())
}

#[cfg(target_os = "macos")]
fn read(account: &str) -> Result<Option<String>, String> {
    match security_framework::passwords::get_generic_password(
        "Switchyard server environment",
        account,
    ) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "The saved server credential is not UTF-8.".into()),
        Err(e) if e.code() == -25300 => Ok(None),
        Err(_) => Err("Could not read the server credential from Keychain.".into()),
    }
}

#[cfg(target_os = "macos")]
fn write(account: &str, key: &str) -> Result<(), String> {
    security_framework::passwords::set_generic_password(
        "Switchyard server environment",
        account,
        key.as_bytes(),
    )
    .map_err(|_| "Could not save the server credential to Keychain.".into())
}

#[cfg(windows)]
fn read(account: &str) -> Result<Option<String>, String> {
    crate::windows::read_credential(&format!("Switchyard:server-env:{account}"))
}
#[cfg(windows)]
fn write(account: &str, key: &str) -> Result<(), String> {
    crate::windows::write_credential(&format!("Switchyard:server-env:{account}"), key)
}
#[cfg(not(any(target_os = "macos", windows)))]
fn read(_account: &str) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    #[ignore = "This test uses native credential storage and real binaries selected by SWITCHYARD_TEST_SERVER and SWITCHYARD_TEST_INSTALLER."]
    fn saved_credential_reaches_real_validator_for_a_candidate_config() {
        #[cfg(target_os = "macos")]
        if let Some(config) = std::env::var_os("SWITCHYARD_TEST_BROKER_CONFIG") {
            let output = Command::new(std::env::var_os("SWITCHYARD_TEST_BROKER").expect("broker"))
                .arg("validate")
                .arg("--server")
                .arg(std::env::var_os("SWITCHYARD_TEST_SERVER").expect("server"))
                .arg("--config")
                .arg(&config)
                .arg("--scope")
                .arg(&config)
                .output()
                .expect("app broker validation");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let dir = tempfile::tempdir().expect("fixture");
        let config = dir.path().join("composite.toml");
        let candidate = dir.path().join("candidate.toml");
        let source = r#"
schema_version=1
[llm_clients.gateway]
format="openai_chat"
base_url="https://example.test/v1"
api_key_env="SWITCHYARD_SAVED_SERVER_FIXTURE_TOKEN"
[targets.answer]
id="fixture/model"
llm_client="gateway"
[routes.fixture]
id="fixture/route"
type="passthrough"
target="answer"
"#;
        std::fs::write(&config, source).expect("config");
        std::fs::write(&candidate, source).expect("candidate");
        let account = account(&config, "SWITCHYARD_SAVED_SERVER_FIXTURE_TOKEN").expect("account");
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                #[cfg(target_os = "macos")]
                let _ = security_framework::passwords::delete_generic_password(
                    "Switchyard server environment",
                    &self.0,
                );
                #[cfg(windows)]
                {
                    let target: Vec<_> = format!("Switchyard:server-env:{}", self.0)
                        .encode_utf16()
                        .chain(Some(0))
                        .collect();
                    unsafe {
                        windows_sys::Win32::Security::Credentials::CredDeleteW(
                            target.as_ptr(),
                            windows_sys::Win32::Security::Credentials::CRED_TYPE_GENERIC,
                            0,
                        );
                    }
                }
            }
        }
        let _cleanup = Cleanup(account);
        {
            // The copied helper owns capture and reads; the signed macOS app has a different identity.
            let broker = dir
                .path()
                .join(crate::executable_name("switchyard-desktop-install"));
            std::fs::copy(
                std::env::var_os("SWITCHYARD_TEST_INSTALLER").expect("installer"),
                &broker,
            )
            .expect("copied broker");
            let output = Command::new(&broker)
                .arg("capture")
                .arg("--server")
                .arg(std::env::var_os("SWITCHYARD_TEST_SERVER").expect("server"))
                .arg("--config")
                .arg(&candidate)
                .arg("--scope")
                .arg(&config)
                .env(
                    "SWITCHYARD_SAVED_SERVER_FIXTURE_TOKEN",
                    "dummy-local-fixture-key",
                )
                .output()
                .expect("capture");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let binary = std::env::var_os("SWITCHYARD_TEST_SERVER").expect("server binary");
        let mut validator = Command::new(&binary);
        validator.arg("--config").arg(&candidate).arg("--dry-run");
        assert!(
            !validator
                .output()
                .expect("without credential")
                .status
                .success()
        );
        {
            validator = Command::new(
                dir.path()
                    .join(crate::executable_name("switchyard-desktop-install")),
            );
            validator
                .arg("validate")
                .arg("--server")
                .arg(&binary)
                .arg("--config")
                .arg(&candidate)
                .arg("--scope")
                .arg(&config);
        }
        assert!(
            validator
                .output()
                .expect("with credential")
                .status
                .success()
        );
        let mut invalid = Command::new(
            dir.path()
                .join(crate::executable_name("switchyard-desktop-install")),
        );
        invalid
            .arg("validate")
            .arg("--server")
            .arg(&binary)
            .arg("--config")
            .arg(&candidate)
            .arg("--scope")
            .arg(&config);
        #[cfg(target_os = "macos")]
        invalid.env("SWITCHYARD_SAVED_SERVER_FIXTURE_TOKEN", "");
        #[cfg(windows)]
        invalid.env("switchyard_saved_server_fixture_token", "");
        // An explicitly empty command value also remains authoritative.
        assert!(!invalid.output().expect("empty credential").status.success());
        #[cfg(target_os = "macos")]
        {
            // A separately signed app must delegate validation to the helper that saved the key.
            let app = dir.path().join("Fixture.app");
            std::fs::create_dir_all(app.join("Contents/MacOS")).expect("bundle");
            std::fs::copy(
                std::env::current_exe().expect("test executable"),
                app.join("Contents/MacOS/fixture"),
            )
            .expect("app executable");
            std::fs::write(app.join("Contents/Info.plist"), "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.nvidia.switchyard.credential-fixture</string><key>CFBundleExecutable</key><string>fixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>").expect("bundle metadata");
            assert!(
                Command::new("codesign")
                    .args(["--force", "--deep", "--sign", "-"])
                    .arg(&app)
                    .status()
                    .expect("sign app")
                    .success()
            );
            let output = Command::new(app.join("Contents/MacOS/fixture"))
                .args(["--exact", "credentials::tests::saved_credential_reaches_real_validator_for_a_candidate_config", "--ignored", "--nocapture"])
                .env("SWITCHYARD_TEST_BROKER_CONFIG", &config)
                .env("SWITCHYARD_TEST_BROKER", dir.path().join("switchyard-desktop-install"))
                .env_remove("SWITCHYARD_SAVED_SERVER_FIXTURE_TOKEN").output().expect("signed app delegate");
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let defaults = crate::Settings::from_env().expect("defaults");
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("port")
                .local_addr()
                .expect("address")
                .port();
            let settings = crate::Settings {
                home: dir.path().join("home"),
                sy_home: dir.path().into(),
                codex_home: dir.path().join("codex"),
                service_dir: dir.path().join("services"),
                port,
                ..defaults
            };
            std::fs::create_dir_all(settings.bin_dir()).expect("installed binaries");
            std::fs::copy(
                dir.path().join("switchyard-desktop-install"),
                settings.binary("switchyard-desktop-install"),
            )
            .expect("installed installer");
            std::fs::copy(
                std::env::var_os("SWITCHYARD_TEST_SERVER").expect("server binary"),
                settings.binary("switchyard-server"),
            )
            .expect("installed server");
            let metadata = dir.path().join("install.toml");
            std::fs::write(&metadata, toml::to_string(&settings).expect("metadata"))
                .expect("metadata file");
            // Drop stops and reaps the real server even if readiness assertions fail.
            struct Server(std::process::Child);
            impl Drop for Server {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let _server = Server(
                Command::new(settings.binary("switchyard-desktop-install"))
                    .args(["serve", "--settings"])
                    .arg(metadata)
                    .env_remove("SWITCHYARD_SAVED_SERVER_FIXTURE_TOKEN")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("installed serve"),
            );
            assert!(crate::wait_for_health(port), "installed server readiness");
        }
    }

    #[test]
    fn config_drives_llm_and_decision_credentials_without_overriding_explicit_environment() {
        let dir = tempfile::tempdir().expect("fixture");
        let config = dir.path().join("candidate.toml");
        let source = r#"
schema_version=1
[llm_clients.gateway]
format="openai_chat"
base_url="https://example.test/v1"
api_key_env="CUSTOM_GATEWAY_TOKEN"
[decision_clients.judge]
format="system_one"
endpoint="https://example.test/decision"
api_key_env="CUSTOM_JUDGE_TOKEN"
timeout_ms=1000
[targets]
[routes]
"#;
        std::fs::write(&config, source).expect("config");
        let mut command = Command::new("unused");
        resolve(
            &mut command,
            &config,
            |name| name == "CUSTOM_GATEWAY_TOKEN",
            |name| {
                assert_eq!(name, "CUSTOM_JUDGE_TOKEN");
                Ok(Some("fixture-token".into()))
            },
        )
        .expect("resolved");
        assert_eq!(
            command.get_envs().collect::<Vec<_>>(),
            vec![(
                std::ffi::OsStr::new("CUSTOM_JUDGE_TOKEN"),
                Some(std::ffi::OsStr::new("fixture-token"))
            )]
        );
        let mut command = Command::new("unused");
        assert!(
            resolve(
                &mut command,
                &config,
                |_| false,
                |_| Err("store unavailable".into())
            )
            .is_err()
        );
        assert_eq!(command.get_envs().count(), 0);
        for name in ["A=B", "A\0B", " "] {
            let source = format!(
                "schema_version=1\n[llm_clients.gateway]\nformat=\"openai_chat\"\nbase_url=\"https://example.test/v1\"\napi_key_env={}\n[targets]\n[routes]",
                serde_json::to_string(name).unwrap()
            );
            std::fs::write(&config, source).expect("invalid reference fixture");
            assert!(
                resolve(
                    &mut command,
                    &config,
                    |_| false,
                    |_| panic!("invalid name must not read credentials")
                )
                .is_err()
            );
        }
        std::fs::write(&config, source).expect("restore config");
        #[cfg(windows)]
        {
            // Windows treats case variants as the same variable, including explicit removals and empty values.
            let mut explicit = Command::new("unused");
            explicit
                .env("custom_gateway_token", "")
                .env_remove("custom_judge_token");
            resolve(
                &mut explicit,
                &config,
                |_| false,
                |_| panic!("explicit environment must not read credentials"),
            )
            .expect("explicit environment");
            assert!(same_variable(
                std::ffi::OsStr::new("custom_é_token"),
                "CUSTOM_É_TOKEN"
            ));
        }
        std::fs::write(&config, "schema_version=1\nunknown=1\n[targets]\n[routes]")
            .expect("malformed config");
        assert!(
            resolve(
                &mut command,
                &config,
                |_| false,
                |_| panic!("invalid config must not read credentials")
            )
            .is_err()
        );
        assert_eq!(command.get_envs().count(), 0);
    }

    #[test]
    fn candidate_uses_installed_config_scope_and_distinct_configs_have_distinct_accounts() {
        let dir = tempfile::tempdir().expect("fixture");
        let first = dir.path().join("first.toml");
        let second = dir.path().join("second.toml");
        std::fs::write(&first, "").expect("first");
        std::fs::write(&second, "").expect("second");
        let future = dir.path().join("future.toml");
        let before = account(&future, "CUSTOM_TOKEN").expect("future scope");
        std::fs::write(&future, "").expect("future config");
        assert_eq!(
            before,
            account(&future, "CUSTOM_TOKEN").expect("installed scope")
        );
        assert_ne!(
            account(&first, "CUSTOM_TOKEN").expect("first"),
            account(&second, "CUSTOM_TOKEN").expect("second")
        );
        #[cfg(unix)]
        {
            let colon = dir.path().join("first.toml:extra");
            std::fs::write(&colon, "").expect("colon scope");
            assert_ne!(
                account(&colon, "TOKEN").expect("colon scope"),
                account(&first, "extra:TOKEN").expect("colon variable")
            );
        }
        #[cfg(unix)]
        {
            let link = dir.path().join("link.toml");
            std::os::unix::fs::symlink(&first, &link).expect("link");
            assert_eq!(
                account(&first, "CUSTOM_TOKEN").expect("first"),
                account(&link, "CUSTOM_TOKEN").expect("link")
            );
        }
    }
}

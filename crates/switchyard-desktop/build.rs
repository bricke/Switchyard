// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // Every host checks both platform exports so a stale Windows icon also fails a macOS build.
    println!("cargo:rerun-if-changed=icons");
    if let Err(error) = switchyard_desktop_icons::export(std::path::Path::new("icons"), true) {
        panic!("{error}");
    }
    #[cfg(any(target_os = "macos", windows))]
    tauri_build::build();
}

// SPDX-License-Identifier: Apache-2.0
//! Build script for IncogID++ KeyOS application.
//! Invokes slint-build to compile ui/app.slint into native Rust UI structs.

fn main() {
    slint_build::compile("ui/app.slint").expect("Failed to compile KeyOS Slint UI specification");
}

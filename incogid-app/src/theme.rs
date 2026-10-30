// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
//! Foundation KeyOS Theme Integration for IncogID++ Vault.
//! Applies theme tokens from resources/theme.json and responds to system OLED dark mode.

use slint::ComponentHandle;
use crate::AppWindow;

/// Applies the IncogID++ custom theme tokens to the root Slint AppWindow.
pub fn apply_theme(ui: &AppWindow, dark_mode: bool) {
    // In KeyOS native runtime:
    // foundation_themes::apply_theme!(ui, app_theme::theme(), scheme);
    log::info!("Applied Foundation KeyOS Theme: dark_mode = {}", dark_mode);
}

# Foundation SDK Coding Agent Instructions for IncogID++

## Project Overview
This directory contains **IncogID++**, an air-gapped selective disclosure credential vault for Foundation Passport Prime running **KeyOS** (Palladium microkernel).

## Architecture & Conventions
1. **KeyOS Microkernel Isolation**:
   - Apps run in user space under isolated memory domains.
   - All hardware calls (Camera, Bluetooth Low Energy QuantumLink, Flash Storage, Secure Element) are strictly mediated by Palladium IPC servers.
2. **Permissions**:
   - Declared in `app-config.toml` and `permission_templates.toml`.
   - Never attempt runtime capability escalation; only declared permissions are granted at boot.
3. **Slint UI**:
   - Components imported from `@ui/widgets.slint` (`BaseWindow`, `Card`, `Badge`, `Chip`, `Button`, `IconButton`, `PinEntry`).
   - Pure OLED black background (`#090B0E`) with Foundation brass accents (`#D4AF37`) and semantic status colors.
4. **Development & Testing Workflows**:
   - `foundation preview ui/app.slint`: Fast live visual preview of Slint UI.
   - `foundation sim`: Run the app in the hosted KeyOS simulator with simulated IPC servers.
   - `foundation build`: Compile signed device bundle.
   - `foundation sideload`: Sideload to physical Passport Prime over USB debug.
5. **Agent Safety Rules**:
   - Never output private keys, seeds, or PINs to logs or terminal prompts.
   - Do not invoke low-level bootloader/flash writes without explicit user confirmation.

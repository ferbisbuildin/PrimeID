#!/usr/bin/env bash
# Run foundation-passport-drive against the running simulator inside the SDK shell.
cd ~/.foundation/sdk/current && exec nix develop . -c bin/foundation-passport-drive --sim "$@"

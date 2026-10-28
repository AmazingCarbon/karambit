# Third-party notices

Karambit is licensed under the Apache License 2.0 (see `LICENSE`). It includes or
depends on the third-party components below, each under its own license.

## Fonts (bundled in `app/ui/fonts/`)

Bricolage Grotesque, JetBrains Mono and Pixelify Sans, each under the SIL Open Font
License 1.1. Copyright notices and the full license text are in the `.txt` file next
to each font.

## Rust crates

Dependencies are listed in `Cargo.lock`; nearly all are MIT and/or Apache-2.0
(also BSD, ISC, Zlib, Unicode-3.0, Unlicense, CC0). The GUI also links these
MPL-2.0 crates, unmodified, from crates.io (source:
https://crates.io): `cssparser`, `cssparser-macros`, `selectors`, `dtoa-short`,
`option-ext`. MPL-2.0 is file-level and does not change Karambit's license.
Regenerate the full list with `cargo about` or `cargo deny list` before a release.

## varlock (@env-spec)

`crates/core/src/envspec.rs` is a hand-ported Rust subset of varlock's @env-spec
parser (`packages/env-spec-parser`, varlock 1.23.0, commit 1b7fa9a), and
`crates/cli/src/secure.rs` follows varlock's `init` behaviour for Bun
(`env = false`). Karambit's `.env.schema` format is compatible with, not identical to,
varlock's. Source: https://github.com/dmno-dev/varlock

MIT License

Copyright (c) 2026 DMNO Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

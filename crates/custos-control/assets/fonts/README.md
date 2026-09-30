# PT Sans

Used to render evidence-pack PDFs (`src/evidence/pdf.rs`), embedded into the
binary at compile time via `include_bytes!`. Chosen because it ships static
Regular/Bold/Italic/BoldItalic files (many current Google Fonts releases are
variable-font-only, which `genpdf`'s font loader doesn't take) and covers the
Latin Extended-A glyphs German and Romanian need (ü, ß, ă, â, î, ș, ț).

Source: https://github.com/google/fonts/tree/main/ofl/ptsans
(upstream: ParaType Ltd., https://www.paratype.com/public)

License: SIL Open Font License 1.1 — see `OFL.txt` in this directory.
Redistribution as part of this software is permitted under that license.

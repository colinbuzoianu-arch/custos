import { StreamLanguage } from '@codemirror/language'
import { clike } from '@codemirror/legacy-modes/mode/clike'

// No official CodeMirror mode exists for Cedar. `clike()` builds a
// StreamParser from a C-like skeleton (keywords/atoms/strings/`//`
// comments/`::`-namespaced identifiers) that's parameterizable rather than
// hard-coded to C - Cedar's actual grammar is close enough to this shape
// (statements, string literals, `Kind::"id"` entity references) that
// configuring it gets reasonable highlighting without writing a full
// parser for one editor.
const keywords = toWordSet(['permit', 'forbid', 'when', 'unless', 'if', 'then', 'else', 'in', 'has', 'like', 'is'])

// Cedar's three fixed request slots, `context`, and its two literals -
// highlighted like other languages highlight `true`/`false`/`self`.
const atoms = toWordSet(['principal', 'action', 'resource', 'context', 'true', 'false'])

function toWordSet(words: string[]): Record<string, boolean> {
  return Object.fromEntries(words.map((word) => [word, true]))
}

export const cedarLanguage = StreamLanguage.define(
  clike({
    name: 'cedar',
    keywords,
    atoms,
    namespaceSeparator: '::',
    multiLineStrings: false,
  }),
)

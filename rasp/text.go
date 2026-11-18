package rasp

import (
	"strings"
	"unicode/utf8"
)

// Helpers that keep string handling aligned with the TypeScript reference.
// Substring search and offsets are on bytes (the contract allows any unit
// within one string); length limits and minimum lengths count characters
// (code points), as Python does, so a non-ASCII input is never judged longer
// than it reads.

// charLen is a string's length in characters (code points).
func charLen(s string) int { return utf8.RuneCountInString(s) }

// truncChars cuts s to at most n characters, never inside a character.
func truncChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := 0
	for k := range s {
		if i == n {
			return s[:k]
		}
		i++
	}
	return s
}

// isJSSpace reports whether r is white space or a line terminator as
// JavaScript's String.prototype.trim and \s see them.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// jsTrim trims as JavaScript's String.prototype.trim does.
func jsTrim(s string) string { return strings.TrimFunc(s, isJSSpace) }

// jsSpaceClass is JavaScript's \s as an RE2 character class body.
const jsSpaceClass = `\t\n\x0b\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// byteAt returns s[i], or 0 past either end (the TypeScript code reads
// undefined there, which matches nothing).
func byteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

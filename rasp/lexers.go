package rasp

import "strings"

// One-pass lexers used by the structural checks: SQL, shell and a generic
// C-like lexer for code. No regex backtracking; every loop advances.
// Offsets are byte offsets into the lexed string.

// Token is one lexed token: [S, E) in the source, its kind and text.
type Token struct {
	S, E int
	Kind string
	Text string
}

// SQLDialect selects the SQL lexer's dialect rules.
type SQLDialect string

// The dialects of the contract.
const (
	DialectMySQL    SQLDialect = "mysql"
	DialectPostgres SQLDialect = "postgres"
	DialectSQLite   SQLDialect = "sqlite"
	DialectMSSQL    SQLDialect = "mssql"
	DialectOracle   SQLDialect = "oracle"
	DialectDB2      SQLDialect = "db2"
	DialectGeneric  SQLDialect = "generic"
)

// SQLDialects lists every dialect the SQL lexer knows (README "SQL").
var SQLDialects = []SQLDialect{DialectMySQL, DialectPostgres, DialectSQLite, DialectMSSQL, DialectOracle, DialectDB2, DialectGeneric}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
func isDigitByte(c byte) bool   { return c >= '0' && c <= '9' }
func isIDStartByte(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' }
func isIDCharByte(c byte) bool  { return isIDStartByte(c) || isDigitByte(c) || c == '$' }
func isHexByte(c byte) bool {
	return isDigitByte(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

var sqlOps = []string{"->>", "<=", ">=", "<>", "!=", "||", "&&", "::", ":=", "->", "<<", ">>"}

// SQLTokens tokenizes SQL per the contract's lexer.
func SQLTokens(q string, dialect SQLDialect) []Token {
	if dialect == "" {
		dialect = DialectGeneric
	}
	var out []Token
	n := len(q)
	hashComment := dialect == DialectMySQL || dialect == DialectGeneric
	bracketIdent := dialect == DialectMSSQL || dialect == DialectGeneric
	dollarQuote := dialect == DialectPostgres || dialect == DialectGeneric
	oracle := dialect == DialectOracle
	db2 := dialect == DialectDB2
	// E'' (backslash escapes) is not a prefix in Oracle or DB2.
	ePrefix := !oracle && !db2
	// Oracle and DB2 identifiers may contain '#' after the first character.
	idChar := func(c byte) bool { return isIDCharByte(c) || ((oracle || db2) && c == '#') }
	push := func(s, e int, kind string) { out = append(out, Token{S: s, E: e, Kind: kind, Text: q[s:e]}) }

	// A quoted run starting at start (q[start] is the quote); returns the end.
	quoted := func(start int, closeQuote byte, backslash bool) int {
		j := start + 1
		for j < n {
			c := q[j]
			if backslash && c == '\\' {
				j += 2
				continue
			}
			if c == closeQuote {
				if byteAt(q, j+1) == closeQuote {
					j += 2
					continue
				}
				return j + 1
			}
			j++
		}
		return n
	}
	// A name part: identifier or quoted identifier; returns its end or -1.
	namePart := func(j int) int {
		if j >= n {
			return -1
		}
		c := q[j]
		if isIDStartByte(c) {
			k := j + 1
			for k < n && idChar(q[k]) {
				k++
			}
			return k
		}
		if c == '"' || c == '`' {
			return quoted(j, c, false)
		}
		if c == '[' && bracketIdent {
			return quoted(j, ']', false)
		}
		return -1
	}
	// Oracle alternative quoting q'X…X' (also nq'…'), the quote at j; returns
	// its end or -1. The delimiter X is one character (a whole UTF-8
	// sequence) other than whitespace.
	altQuoted := func(j int) int {
		if j+1 >= n || isSpaceByte(q[j+1]) {
			return -1
		}
		w := utf8SeqLen(q, j+1)
		closeDelim := q[j+1 : j+1+w]
		switch closeDelim {
		case "[":
			closeDelim = "]"
		case "{":
			closeDelim = "}"
		case "(":
			closeDelim = ")"
		case "<":
			closeDelim = ">"
		}
		k := strings.Index(q[j+1+w:], closeDelim+"'")
		if k < 0 {
			return n
		}
		return j + 1 + w + k + len(closeDelim) + 1
	}
	// A block comment starting at i; nests in db2, postgres and mssql.
	nested := dialect == DialectDB2 || dialect == DialectPostgres || dialect == DialectMSSQL
	blockComment := func(i int) int {
		if !nested {
			k := strings.Index(q[i+2:], "*/")
			if k < 0 {
				return n
			}
			return i + 2 + k + 2
		}
		depth := 1
		k := i + 2
		for k < n {
			switch {
			case q[k] == '/' && byteAt(q, k+1) == '*':
				depth++
				k += 2
			case q[k] == '*' && byteAt(q, k+1) == '/':
				k += 2
				depth--
				if depth == 0 {
					return k
				}
			default:
				k++
			}
		}
		return n
	}
	toEOL := func(i int) int {
		k := strings.IndexByte(q[i:], '\n')
		if k < 0 {
			return n
		}
		return i + k
	}

	i := 0
	for i < n {
		c := q[i]
		if isSpaceByte(c) {
			i++
			continue
		}
		start := i
		// comments
		if c == '-' && byteAt(q, i+1) == '-' {
			i = toEOL(i)
			push(start, i, "comment")
			continue
		}
		if c == '#' && hashComment {
			i = toEOL(i)
			push(start, i, "comment")
			continue
		}
		if c == '/' && byteAt(q, i+1) == '*' {
			i = blockComment(i)
			kind := "comment"
			if byteAt(q, start+2) == '!' {
				kind = "version_comment"
			}
			push(start, i, kind)
			continue
		}
		// strings, with E'' / N'' prefixes
		if c == '\'' {
			i = quoted(i, '\'', dialect == DialectMySQL)
			push(start, i, "string")
			continue
		}
		if oracle {
			// q'…' / nq'…' alternative quoting
			p := i
			if c == 'N' || c == 'n' {
				p = i + 1
			}
			if (byteAt(q, p) == 'q' || byteAt(q, p) == 'Q') && byteAt(q, p+1) == '\'' {
				if k := altQuoted(p + 1); k > 0 {
					i = k
					push(start, i, "string")
					continue
				}
			}
		}
		if db2 {
			// X'' hex, G'' graphic, GX'' / UX'' / BX'' hex strings
			isX := func(b byte) bool { return b == 'X' || b == 'x' }
			g := c == 'G' || c == 'g'
			p := i
			if (g || c == 'U' || c == 'u' || c == 'B' || c == 'b') && isX(byteAt(q, i+1)) {
				p = i + 1
			}
			if (p > i || g || isX(c)) && byteAt(q, p+1) == '\'' {
				i = quoted(p+1, '\'', false)
				push(start, i, "string")
				continue
			}
		}
		if (((c == 'E' || c == 'e') && ePrefix) || c == 'N' || c == 'n') && byteAt(q, i+1) == '\'' {
			i = quoted(i+1, '\'', dialect == DialectMySQL || c == 'E' || c == 'e')
			push(start, i, "string")
			continue
		}
		// dollar quotes and $n placeholders
		if c == '$' {
			if isDigitByte(byteAt(q, i+1)) {
				k := i + 1
				for k < n && isDigitByte(q[k]) {
					k++
				}
				i = k
				push(start, i, "placeholder")
				continue
			}
			if dollarQuote {
				k := i + 1
				for k < n && (isIDStartByte(q[k]) || isDigitByte(q[k])) {
					k++
				}
				if byteAt(q, k) == '$' {
					tag := q[i : k+1]
					end := strings.Index(q[k+1:], tag)
					if end < 0 {
						i = n
					} else {
						i = k + 1 + end + len(tag)
					}
					push(start, i, "string")
					continue
				}
			}
		}
		// placeholders
		if c == '?' {
			i++
			push(start, i, "placeholder")
			continue
		}
		if (c == ':' || c == '@') && isIDStartByte(byteAt(q, i+1)) && !(c == ':' && byteAt(q, i-1) == ':') {
			k := i + 1
			for k < n && idChar(q[k]) {
				k++
			}
			i = k
			push(start, i, "placeholder")
			continue
		}
		if oracle && c == ':' && isDigitByte(byteAt(q, i+1)) && byteAt(q, i-1) != ':' {
			// Oracle positional bind :1
			k := i + 1
			for k < n && isDigitByte(q[k]) {
				k++
			}
			i = k
			push(start, i, "placeholder")
			continue
		}
		if c == '@' && byteAt(q, i+1) == '@' && isIDStartByte(byteAt(q, i+2)) {
			k := i + 2
			for k < n && isIDCharByte(q[k]) {
				k++
			}
			i = k
			push(start, i, "word")
			continue
		}
		if c == '%' && byteAt(q, i+1) == 's' {
			i += 2
			push(start, i, "placeholder")
			continue
		}
		if c == '%' && byteAt(q, i+1) == '(' {
			if k := strings.IndexByte(q[i+2:], ')'); k >= 0 {
				k += i + 2
				if byteAt(q, k+1) == 's' {
					i = k + 2
					push(start, i, "placeholder")
					continue
				}
			}
		}
		// numbers
		if isDigitByte(c) || (c == '.' && isDigitByte(byteAt(q, i+1))) {
			k := i
			if c == '0' && (byteAt(q, i+1) == 'x' || byteAt(q, i+1) == 'X') {
				k = i + 2
				for k < n && isHexByte(q[k]) {
					k++
				}
			} else {
				for k < n && isDigitByte(q[k]) {
					k++
				}
				if byteAt(q, k) == '.' {
					k++
					for k < n && isDigitByte(q[k]) {
						k++
					}
				}
				e := byteAt(q, k)
				if (e == 'e' || e == 'E') && (isDigitByte(byteAt(q, k+1)) || ((byteAt(q, k+1) == '+' || byteAt(q, k+1) == '-') && isDigitByte(byteAt(q, k+2)))) {
					k += 2
					for k < n && isDigitByte(q[k]) {
						k++
					}
				}
			}
			i = k
			push(start, i, "number")
			continue
		}
		// identifiers and qualified names (one token)
		if first := namePart(i); first > 0 {
			k := first
			for byteAt(q, k) == '.' {
				next := namePart(k + 1)
				if next < 0 {
					break
				}
				k = next
			}
			i = k
			kind := "name"
			if isIDStartByte(c) && k == first {
				kind = "word"
			}
			push(start, i, kind)
			continue
		}
		// operators
		width := 1
		for _, op := range sqlOps {
			if strings.HasPrefix(q[i:], op) {
				width = len(op)
				break
			}
		}
		i += width
		push(start, i, "op")
	}
	return out
}

var shellOps = []string{"&&", "||", ">>", "<<", "$(", ";", "&", "|", ">", "<", "(", ")", "`", "\n"}

// ShellTokens returns the shell tokens of cmd and, per byte, whether it lies
// inside single quotes.
func ShellTokens(cmd string) (tokens []Token, inSingle []bool) {
	n := len(cmd)
	inSingle = make([]bool, n)
	i := 0
	wordStart := -1
	dq := false
	endWord := func(e int) {
		if wordStart >= 0 && e > wordStart {
			tokens = append(tokens, Token{S: wordStart, E: e, Kind: "word", Text: cmd[wordStart:e]})
		}
		wordStart = -1
	}
	for i < n {
		c := cmd[i]
		if !dq {
			if c == ' ' || c == '\t' {
				endWord(i)
				i++
				continue
			}
			op := ""
			for _, o := range shellOps {
				if strings.HasPrefix(cmd[i:], o) {
					op = o
					break
				}
			}
			if op != "" {
				endWord(i)
				tokens = append(tokens, Token{S: i, E: i + len(op), Kind: "op", Text: op})
				i += len(op)
				continue
			}
			if wordStart < 0 {
				wordStart = i
			}
			if c == '\\' {
				i += 2
				continue
			}
			if c == '\'' {
				end := n
				if k := strings.IndexByte(cmd[i+1:], '\''); k >= 0 {
					end = i + 1 + k + 1
				}
				for j := i; j < end; j++ {
					inSingle[j] = true
				}
				i = end
				continue
			}
			if c == '"' {
				dq = true
				i++
				continue
			}
			i++
			continue
		}
		// inside double quotes
		if c == '\\' {
			if wordStart < 0 {
				wordStart = i
			}
			i += 2
			continue
		}
		if c == '"' {
			if wordStart < 0 {
				wordStart = i
			}
			dq = false
			i++
			continue
		}
		if c == '`' || (c == '$' && byteAt(cmd, i+1) == '(') {
			endWord(i)
			l := 2
			if c == '`' {
				l = 1
			}
			tokens = append(tokens, Token{S: i, E: i + l, Kind: "op", Text: cmd[i : i+l]})
			i += l
			continue
		}
		if wordStart < 0 {
			wordStart = i
		}
		i++
	}
	if i > n {
		i = n
	}
	endWord(n)
	return tokens, inSingle
}

// CodeTokens is a generic C-like lexer: identifiers, numbers, quoted
// strings, comments, punctuation. Bytes above 0x7f join identifiers.
func CodeTokens(src string) []Token {
	var out []Token
	n := len(src)
	i := 0
	for i < n {
		c := src[i]
		if isSpaceByte(c) {
			i++
			continue
		}
		s := i
		if c == '/' && byteAt(src, i+1) == '/' {
			if k := strings.IndexByte(src[i:], '\n'); k >= 0 {
				i += k
			} else {
				i = n
			}
			out = append(out, Token{S: s, E: i, Kind: "comment", Text: src[s:i]})
			continue
		}
		if c == '/' && byteAt(src, i+1) == '*' {
			if k := strings.Index(src[i+2:], "*/"); k >= 0 {
				i = i + 2 + k + 2
			} else {
				i = n
			}
			out = append(out, Token{S: s, E: i, Kind: "comment", Text: src[s:i]})
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			k := i + 1
			for k < n && src[k] != c {
				if src[k] == '\\' {
					k += 2
				} else {
					k++
				}
			}
			i = min(n, k+1)
			out = append(out, Token{S: s, E: i, Kind: "string", Text: src[s:i]})
			continue
		}
		if isDigitByte(c) {
			k := i + 1
			for k < n && (isIDCharByte(src[k]) || src[k] == '.') {
				k++
			}
			i = k
			out = append(out, Token{S: s, E: i, Kind: "number", Text: src[s:i]})
			continue
		}
		if isIDStartByte(c) || c == '$' || c > 127 {
			k := i + 1
			for k < n && (isIDCharByte(src[k]) || src[k] > 127) {
				k++
			}
			i = k
			out = append(out, Token{S: s, E: i, Kind: "word", Text: src[s:i]})
			continue
		}
		i++
		out = append(out, Token{S: s, E: i, Kind: "op", Text: string(c)})
	}
	return out
}

// Overlapping returns the tokens overlapping [idx, idx+n): s < idx+n && e > idx.
func Overlapping(tokens []Token, idx, n int) []Token {
	end := idx + n
	var out []Token
	for _, t := range tokens {
		if t.S >= end {
			break
		}
		if t.E > idx {
			out = append(out, t)
		}
	}
	return out
}

// countOverlapping is Overlapping's length without the allocation.
func countOverlapping(tokens []Token, idx, n int) int {
	end := idx + n
	c := 0
	for _, t := range tokens {
		if t.S >= end {
			break
		}
		if t.E > idx {
			c++
		}
	}
	return c
}

// Occurrences returns the start offsets of needle in hay, at most max.
func Occurrences(hay, needle string, max int) []int {
	var out []int
	if needle == "" {
		return out
	}
	from := 0
	for len(out) < max && from <= len(hay) {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			break
		}
		out = append(out, from+i)
		from += i + 1
	}
	return out
}

// utf8SeqLen is the length of the UTF-8 sequence at q[i]: 2 to 4 for a lead
// byte followed by enough continuation bytes, else 1.
func utf8SeqLen(q string, i int) int {
	c := q[i]
	w := 1
	switch {
	case c >= 0xC0 && c <= 0xDF:
		w = 2
	case c >= 0xE0 && c <= 0xEF:
		w = 3
	case c >= 0xF0 && c <= 0xF7:
		w = 4
	}
	if i+w > len(q) {
		return 1
	}
	for k := i + 1; k < i+w; k++ {
		if q[k] < 0x80 || q[k] > 0xBF {
			return 1
		}
	}
	return w
}

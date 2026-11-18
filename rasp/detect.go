package rasp

import (
	"encoding/base64"
	"math"
	"os"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Pure structural detectors (README "Detection algorithms"). Each takes the
// sink's argument and the inputs in scope and returns a *Finding or nil. No
// I/O and no state: the engine decides what a finding does.

func reqInputs(inputs []Input, minLen int) []*Input {
	var out []*Input
	for i := range inputs {
		if inputs[i].Source == SourceRequest && charLen(inputs[i].Value) >= minLen {
			out = append(out, &inputs[i])
		}
	}
	return out
}

func modelInputs(inputs []Input, minLen int) []*Input {
	var out []*Input
	for i := range inputs {
		if inputs[i].Source == SourceModelOutput && charLen(inputs[i].Value) >= minLen {
			out = append(out, &inputs[i])
		}
	}
	return out
}

func found(attack AttackType, rule string, in *Input) *Finding {
	var cp *Input
	if in != nil {
		c := *in
		cp = &c
	}
	return &Finding{Attack: attack, Rule: rule, Input: cp}
}

// ---- SQL ----------------------------------------------------------------

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

var (
	antiDetect      = wordSet("add all alter analyze and any as asc avg begin between by case create count delete desc do dumpfile else elseif end exists false file float flush follows from group having identified if in insert interval into join last like limit loop not null on or order procedure regexp return rlike select then true union update values xor")
	commaList       = regexp.MustCompile(`^(, *)?(([a-zA-Z_]\w*|[0-9+\-x.]+) *, *)+([a-zA-Z_]\w*|[0-9+\-x.]+)$`)
	writeStatements = wordSet("insert update delete drop alter create truncate grant revoke merge replace")
)

func isCommentToken(t Token) bool { return t.Kind == "comment" || t.Kind == "version_comment" }

// hasStackedAfter: among from (tokens of all) a ; operator followed by a
// non-comment token somewhere in all.
func hasStackedAfter(all, from []Token) bool {
	for _, t := range from {
		if t.Kind != "op" || t.Text != ";" {
			continue
		}
		at := -1
		for k := range all {
			if all[k].S == t.S && all[k].E == t.E {
				at = k
				break
			}
		}
		for _, x := range all[at+1:] {
			if !isCommentToken(x) {
				return true
			}
		}
	}
	return false
}

func sqlWholeIsDangerous(tokens []Token) bool {
	var code []Token
	for _, t := range tokens {
		if !isCommentToken(t) {
			code = append(code, t)
		}
	}
	if len(code) == 0 {
		return false
	}
	if code[0].Kind == "word" && writeStatements[strings.ToLower(code[0].Text)] {
		return true
	}
	for i := 0; i < len(code)-1; i++ {
		if code[i].Kind == "op" && code[i].Text == ";" {
			return true
		}
	}
	return false
}

// DetectSQL runs the sql_injection rules: sqli.userinput, sqli.stacked,
// sqli.model_output.
func DetectSQL(query string, inputs []Input, dialect SQLDialect) *Finding {
	return detectSQLWith(query, inputs, dialect, nil)
}

// detectSQLWith wraps the SQL rules so every finding carries the dialect the
// lexer used.
func detectSQLWith(query string, inputs []Input, dialect SQLDialect, slot *iastSlot) *Finding {
	f := detectSQLRules(query, inputs, dialect, slot)
	if f != nil {
		if dialect == "" {
			dialect = DialectGeneric
		}
		f.Dialect = dialect
	}
	return f
}

// detectSQLRules is DetectSQL that notes a passive IAST vulnerability in slot
// when no attack is found.
func detectSQLRules(query string, inputs []Input, dialect SQLDialect, slot *iastSlot) *Finding {
	if query == "" || len(inputs) == 0 {
		return nil
	}
	var tokens []Token
	lexed := false
	toks := func() []Token {
		if !lexed {
			tokens, lexed = SQLTokens(query, dialect), true
		}
		return tokens
	}
	trimmed := jsTrim(query)
	for _, inp := range reqInputs(inputs, 3) {
		v := inp.Value
		if v == query || jsTrim(v) == trimmed {
			continue // allow_full: a SQL console
		}
		occ := Occurrences(query, v, 8)
		if len(occ) == 0 {
			continue
		}
		isList := commaList.MatchString(v)
		for _, idx := range occ {
			over := Overlapping(toks(), idx, len(v))
			if !isList && len(over) >= 2 {
				if len(over) >= 10 {
					return found(SQLInjection, "sqli.userinput", inp)
				}
				plain := 0
				for _, t := range over {
					if !(t.Kind == "word" && antiDetect[strings.ToLower(t.Text)]) {
						plain++
					}
				}
				if plain >= 2 {
					return found(SQLInjection, "sqli.userinput", inp)
				}
			}
			if hasStackedAfter(toks(), over) {
				return found(SQLInjection, "sqli.stacked", inp)
			}
		}
	}
	for _, inp := range modelInputs(inputs, 3) {
		if jsTrim(inp.Value) == trimmed {
			if sqlWholeIsDangerous(toks()) {
				return found(SQLInjection, "sqli.model_output", inp)
			}
			continue
		}
		for _, idx := range Occurrences(query, inp.Value, 8) {
			if countOverlapping(toks(), idx, len(inp.Value)) >= 2 {
				return found(SQLInjection, "sqli.model_output", inp)
			}
		}
	}
	slot.note(func() *vuln { return vulnSQL(query, inputs, toks) }) // passive IAST
	return nil
}

// ---- NoSQL ----------------------------------------------------------------

// node is a document node seen generically: an object (string keys), an
// array, or a scalar. Maps with string keys, slices, and slices of
// {Key, Value} structs (bson.D) are objects or arrays.
type node struct {
	keys    []string
	vals    []any
	isArray bool
	ptr     uintptr // identity of the underlying map or slice
	ok      bool
}

func nodeOf(v any) node {
	if v == nil {
		return node{}
	}
	switch m := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		vals := make([]any, len(keys))
		for i, k := range keys {
			vals[i] = m[k]
		}
		return node{keys: keys, vals: vals, ptr: reflect.ValueOf(m).Pointer(), ok: true}
	case []any:
		n := node{isArray: true, ptr: reflect.ValueOf(m).Pointer(), ok: true, vals: m}
		n.keys = make([]string, len(m))
		for i := range m {
			n.keys[i] = strconv.Itoa(i)
		}
		if len(m) == 0 {
			n.ptr = 0
		}
		return n
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return node{}
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return node{}
		}
		mk := rv.MapKeys()
		sort.Slice(mk, func(a, b int) bool { return mk[a].String() < mk[b].String() })
		n := node{ptr: rv.Pointer(), ok: true}
		for _, k := range mk {
			n.keys = append(n.keys, k.String())
			n.vals = append(n.vals, rv.MapIndex(k).Interface())
		}
		return n
	case reflect.Slice, reflect.Array:
		et := rv.Type().Elem()
		if et.Kind() == reflect.Uint8 {
			return node{}
		}
		n := node{isArray: true, ok: true}
		if rv.Kind() == reflect.Slice && rv.Len() > 0 {
			n.ptr = rv.Pointer()
		}
		// bson.D and similar: ordered {Key, Value} pairs form an object.
		if et.Kind() == reflect.Struct {
			if kf, okK := et.FieldByName("Key"); okK && kf.Type.Kind() == reflect.String {
				if _, okV := et.FieldByName("Value"); okV {
					n.isArray = false
					for i := 0; i < rv.Len(); i++ {
						e := rv.Index(i)
						n.keys = append(n.keys, e.FieldByName("Key").String())
						n.vals = append(n.vals, e.FieldByName("Value").Interface())
					}
					return n
				}
			}
		}
		for i := 0; i < rv.Len(); i++ {
			n.keys = append(n.keys, strconv.Itoa(i))
			n.vals = append(n.vals, rv.Index(i).Interface())
		}
		return n
	}
	return node{}
}

func asFloat(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	case reflect.String:
		if n, ok := v.(interface{ Float64() (float64, error) }); ok {
			f, err := n.Float64()
			return f, err == nil
		}
	}
	return 0, false
}

// sameScalar is JavaScript's === on scalars (numbers compared as numbers).
func sameScalar(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if fa, ok := asFloat(a); ok {
		fb, ok := asFloat(b)
		return ok && fa == fb && !math.IsNaN(fa)
	}
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	switch {
	case ra.Kind() == reflect.String && rb.Kind() == reflect.String:
		return ra.String() == rb.String()
	case ra.Kind() == reflect.Bool && rb.Kind() == reflect.Bool:
		return ra.Bool() == rb.Bool()
	}
	return false
}

func identical(a, b node) bool {
	return a.ok && b.ok && a.ptr != 0 && a.ptr == b.ptr && a.isArray == b.isArray
}

func deepEqualAny(a, b any, depth int) bool {
	na, nb := nodeOf(a), nodeOf(b)
	if !na.ok || !nb.ok {
		if na.ok || nb.ok {
			return false
		}
		return sameScalar(a, b)
	}
	if identical(na, nb) {
		return true
	}
	if depth > 32 || na.isArray != nb.isArray || len(na.keys) != len(nb.keys) {
		return false
	}
	idx := make(map[string]int, len(nb.keys))
	for i, k := range nb.keys {
		idx[k] = i
	}
	for i, k := range na.keys {
		j, ok := idx[k]
		if !ok || !deepEqualAny(na.vals[i], nb.vals[j], depth+1) {
			return false
		}
	}
	return true
}

func treeContains(tree, obj any, depth int) bool {
	nt := nodeOf(tree)
	if !nt.ok || depth > 32 {
		return false
	}
	if identical(nt, nodeOf(obj)) || deepEqualAny(tree, obj, 0) {
		return true
	}
	for _, v := range nt.vals {
		if treeContains(v, obj, depth+1) {
			return true
		}
	}
	return false
}

// DetectNoSQL runs nosqli.operator (an operator object of the request
// reaches the driver) and nosqli.where (tainted code in $where/$function).
func DetectNoSQL(doc any, trees []any, inputs []Input) *Finding {
	var hit *Finding
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if hit != nil || depth > 32 {
			return
		}
		n := nodeOf(v)
		if !n.ok {
			return
		}
		if !n.isArray {
			hasOp := false
			for _, k := range n.keys {
				if strings.HasPrefix(k, "$") {
					hasOp = true
					break
				}
			}
			if hasOp {
				for _, t := range trees {
					if treeContains(t, v, 0) {
						hit = &Finding{Attack: NoSQLInjection, Rule: "nosqli.operator"}
						return
					}
				}
			}
		}
		for i, k := range n.keys {
			if (k == "$where" || k == "$function") && hit == nil {
				code := ""
				if s, ok := n.vals[i].(string); ok {
					code = s
				} else if b := nodeOf(n.vals[i]); b.ok && !b.isArray {
					for j, bk := range b.keys {
						if bk == "body" {
							code, _ = b.vals[j].(string)
						}
					}
				}
				if code != "" {
					if f := DetectCode(code, inputs); f != nil {
						hit = &Finding{Attack: NoSQLInjection, Rule: "nosqli.where", Input: f.Input}
					}
				}
			}
			walk(n.vals[i], depth+1)
		}
	}
	walk(doc, 0)
	return hit
}

// ---- Command ----------------------------------------------------------------

var (
	shells      = wordSet("sh bash zsh dash ksh fish csh tcsh cmd powershell pwsh")
	downloaders = wordSet("curl wget")
	multiOps    = map[string]bool{";": true, "&&": true, "||": true, "|": true, "`": true, "$(": true}
)

// ExeName is an executable's basename, lower-cased, without .exe.
func ExeName(p string) string {
	base := strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(base), ".exe")
}

// IsShell reports whether an executable's basename is a shell.
func IsShell(p string) bool { return shells[ExeName(p)] }

func unquoteWord(w string) string {
	if len(w) > 0 && (w[0] == '\'' || w[0] == '"') {
		w = w[1:]
	}
	if len(w) > 0 && (w[len(w)-1] == '\'' || w[len(w)-1] == '"') {
		w = w[:len(w)-1]
	}
	return w
}

// DetectCommand runs the command_injection rules on a shell-interpreted
// command: cmdi.userinput, cmdi.substitution, cmdi.full, cmdi.model_output.
func DetectCommand(command string, inputs []Input) *Finding {
	return detectCommandWith(command, inputs, nil)
}

func detectCommandWith(command string, inputs []Input, slot *iastSlot) *Finding {
	if command == "" || len(inputs) == 0 {
		return nil
	}
	tokens, inSingle := ShellTokens(command)
	trimmed := jsTrim(command)
	req3 := reqInputs(inputs, 3)
	for _, inp := range req3 {
		for _, idx := range Occurrences(command, inp.Value, 8) {
			if countOverlapping(tokens, idx, len(inp.Value)) >= 2 {
				return found(CommandInjection, "cmdi.userinput", inp)
			}
		}
	}
	for _, inp := range req3 {
		v := inp.Value
		if strings.Contains(v, "${IFS}") || strings.Contains(v, "$IFS") {
			if strings.Contains(command, v) {
				return found(CommandInjection, "cmdi.substitution", inp)
			}
		}
		if strings.Contains(v, "`") || strings.Contains(v, "$(") {
			for _, idx := range Occurrences(command, v, 8) {
				for k := idx; k < idx+len(v); k++ {
					sub := command[k] == '`' || (command[k] == '$' && byteAt(command, k+1) == '(')
					if sub && !inSingle[k] {
						return found(CommandInjection, "cmdi.substitution", inp)
					}
				}
			}
		}
	}
	for _, inp := range reqInputs(inputs, 1) {
		if jsTrim(inp.Value) == trimmed {
			return found(CommandInjection, "cmdi.full", inp)
		}
	}
	for _, inp := range modelInputs(inputs, 3) {
		if jsTrim(inp.Value) == trimmed {
			for _, t := range tokens {
				if t.Kind == "op" && multiOps[t.Text] {
					return found(CommandInjection, "cmdi.model_output", inp)
				}
			}
			continue
		}
		for _, idx := range Occurrences(command, inp.Value, 8) {
			if countOverlapping(tokens, idx, len(inp.Value)) >= 2 {
				return found(CommandInjection, "cmdi.model_output", inp)
			}
		}
	}
	slot.note(func() *vuln { return vulnShell(command, inputs, tokens) }) // passive IAST
	return nil
}

// DetectArgv runs cmdi.executable on an argv spawn: argv[0] equals an input.
func DetectArgv(argv []string, inputs []Input) *Finding {
	return detectArgvWith(argv, inputs, nil)
}

func detectArgvWith(argv []string, inputs []Input, slot *iastSlot) *Finding {
	if len(argv) == 0 {
		return nil
	}
	for i := range inputs {
		if inputs[i].Value != "" && inputs[i].Value == argv[0] {
			return found(CommandInjection, "cmdi.executable", &inputs[i])
		}
	}
	// Passive IAST: a sh -c <script> spawn's script is checked as shell text
	// instead.
	slot.note(func() *vuln {
		if script, ok := ShellScriptOf(argv); ok && script != "" {
			return nil
		}
		return vulnArgv(argv, inputs)
	})
	return nil
}

// Spawn describes a process start for DetectShellSpawn.
type Spawn struct {
	// Argv0 is the executable spawned explicitly, if any.
	Argv0 string
	// Command is the command line of a shell-interpreted call, if any.
	Command   string
	InRequest bool
	// Allow is allow.commands.
	Allow []string
}

// DetectShellSpawn runs shell_spawn.download_exec (at any time) and
// shell_spawn.shell (during a request, unless allowed).
func DetectShellSpawn(s Spawn) *Finding {
	allowed := map[string]bool{}
	for _, a := range s.Allow {
		allowed[ExeName(a)] = true
	}
	if s.Command != "" {
		words, _ := ShellTokens(s.Command)
		for i := range words {
			if words[i].Kind != "word" || !downloaders[ExeName(unquoteWord(words[i].Text))] {
				continue
			}
			for k := i + 1; k < len(words)-1; k++ {
				if words[k].Kind == "op" && words[k].Text == "|" && words[k+1].Kind == "word" && shells[ExeName(unquoteWord(words[k+1].Text))] {
					return &Finding{Attack: ShellSpawn, Rule: "shell_spawn.download_exec"}
				}
			}
		}
	}
	if !s.InRequest {
		return nil
	}
	name := ""
	if s.Argv0 != "" {
		name = ExeName(s.Argv0)
	}
	if name == "" && s.Command != "" {
		words, _ := ShellTokens(s.Command)
		for _, t := range words {
			if t.Kind == "word" {
				name = ExeName(unquoteWord(t.Text))
				break
			}
		}
	}
	if name != "" && (shells[name] || downloaders[name]) && !allowed[name] {
		return &Finding{Attack: ShellSpawn, Rule: "shell_spawn.shell", Target: name}
	}
	return nil
}

// ShellScriptOf returns the script of a `sh -c <script>` style argv, if any.
func ShellScriptOf(argv []string) (string, bool) {
	if len(argv) < 3 || !shells[ExeName(argv[0])] {
		return "", false
	}
	for i := 1; i < len(argv); i++ {
		a := strings.ToLower(argv[i])
		if argv[i] == "-c" || a == "/c" || a == "-command" {
			if i+1 < len(argv) {
				return strings.Join(argv[i+1:], " "), true
			}
			return "", false
		}
	}
	return "", false
}

// ---- Path ----------------------------------------------------------------

var (
	multiSlash = regexp.MustCompile(`/{2,}`)
	drivePath  = regexp.MustCompile(`^[A-Za-z]:/`)
	driveOnly  = regexp.MustCompile(`^[A-Za-z]:`)
	scriptFile = regexp.MustCompile(`(?i)\.(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)\.?$`)
	ntfsStream = regexp.MustCompile(`(?i)::\$(DATA|INDEX)$`)
	sensitive  = []string{"/etc/passwd", "/etc/shadow", "/proc/self/environ", "/root/.bash_history", "/var/run/secrets/kubernetes.io/serviceaccount/token"}
)

// NormPath turns \ into / and collapses /./ and //, keeping a UNC prefix.
func NormPath(p string) string {
	s := strings.ReplaceAll(p, "\\", "/")
	unc := strings.HasPrefix(s, "//")
	for strings.Contains(s, "/./") {
		s = strings.Replace(s, "/./", "/", 1)
	}
	s = multiSlash.ReplaceAllString(s, "/")
	if unc {
		return "/" + s
	}
	return s
}

func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "/"
	}
	return d
}

// ResolvePath joins a relative path to dir (the working directory when
// empty), turns \ into / and removes . and .. lexically.
func ResolvePath(p, dir string) string {
	s := strings.ReplaceAll(p, "\\", "/")
	abs := s
	if !strings.HasPrefix(s, "/") && !drivePath.MatchString(s) {
		if dir == "" {
			dir = cwd()
		}
		abs = strings.ReplaceAll(dir, "\\", "/") + "/" + s
	}
	drive := ""
	if driveOnly.MatchString(abs) {
		drive = abs[:2]
	}
	r := drive + strings.TrimSuffix(path.Clean("/"+abs[len(drive):]), "/")
	if r == "" {
		return "/"
	}
	return r
}

// UnderRoot reports whether resolved equals root or lies under it.
func UnderRoot(resolved, root string) bool {
	r := ResolvePath(root, "")
	if resolved == r {
		return true
	}
	if !strings.HasSuffix(r, "/") {
		r += "/"
	}
	return strings.HasPrefix(resolved, r)
}

// FileOp is the kind of file access a path check judges.
type FileOp string

// The file operations of the contract.
const (
	OpRead   FileOp = "read"
	OpWrite  FileOp = "write"
	OpAppend FileOp = "append"
	OpDelete FileOp = "delete"
	OpRename FileOp = "rename"
	OpList   FileOp = "list"
	OpOpen   FileOp = "open"
)

// DetectPath runs the path_traversal and file_write rules.
func DetectPath(p string, op FileOp, inputs []Input, fileRoots []string, inRequest bool) *Finding {
	return detectPathWith(p, op, inputs, fileRoots, inRequest, nil)
}

func detectPathWith(p string, op FileOp, inputs []Input, fileRoots []string, inRequest bool, slot *iastSlot) *Finding {
	if p == "" {
		return nil
	}
	np := NormPath(p)
	resolved := ResolvePath(p, "")
	writes := op == OpWrite || op == OpAppend || op == OpRename || op == OpOpen
	if writes && ntfsStream.MatchString(p) {
		return &Finding{Attack: FileWrite, Rule: "file_write.ntfs"}
	}
	cands := append(reqInputs(inputs, 3), modelInputs(inputs, 3)...)
	for _, inp := range cands {
		ni := NormPath(inp.Value)
		if strings.Contains(ni, "../") && (strings.HasSuffix(np, ni) || strings.Contains(np, ni)) {
			return found(PathTraversal, "path.traversal", inp)
		}
		isFileURL := strings.HasPrefix(inp.Value, "file://")
		if strings.HasPrefix(ni, "/") || drivePath.MatchString(ni) || isFileURL {
			target := ni
			if isFileURL {
				target = NormPath(inp.Value[7:])
			}
			if np == target || strings.HasSuffix(np, target) {
				return found(PathTraversal, "path.absolute", inp)
			}
		}
		if nul := strings.IndexByte(inp.Value, 0); nul > 0 && strings.Contains(p, inp.Value[:nul]) {
			return found(PathTraversal, "path.nullbyte", inp)
		}
	}
	var contained *Input
	for _, inp := range cands {
		if strings.Contains(p, inp.Value) || strings.Contains(np, NormPath(inp.Value)) {
			contained = inp
			break
		}
	}
	inSomeRoot := func() bool {
		for _, r := range fileRoots {
			if UnderRoot(resolved, r) {
				return true
			}
		}
		return false
	}
	if contained != nil && len(fileRoots) > 0 && !inSomeRoot() {
		f := found(PathTraversal, "path.outside_root", contained)
		f.Target = TargetDirectory(resolved)
		return f
	}
	if contained != nil {
		home, _ := os.UserHomeDir()
		home = strings.ReplaceAll(home, "\\", "/")
		hit := resolved == home+"/.ssh/id_rsa" || strings.HasSuffix(resolved, "/.ssh/id_rsa")
		for _, s := range sensitive {
			hit = hit || resolved == s
		}
		if hit {
			return found(PathTraversal, "path.sensitive", contained)
		}
	}
	if writes && inRequest {
		base := resolved
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if scriptFile.MatchString(base) && (contained != nil || inSomeRoot() || UnderRoot(resolved, os.TempDir())) {
			return found(FileWrite, "file_write.script", contained)
		}
	}
	slot.note(func() *vuln { return vulnPath(np, inputs) }) // passive IAST
	return nil
}

// DetectUpload is file_write.upload: an uploaded file whose name (its last
// path segment) is a script (README "Path").
func DetectUpload(input Input) *Finding {
	name := input.Value
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if !scriptFile.MatchString(name) {
		return nil
	}
	return found(FileWrite, "file_write.upload", &input)
}

// ---- SSRF ----------------------------------------------------------------

var (
	ssrfProtocols = wordSet("file gopher dict ftp jar netdoc ldap ldaps php phar expect tftp")
	// MetadataHosts are the cloud metadata addresses of ssrf.metadata.
	MetadataHosts = []string{"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "169.254.170.2", "metadata.google.internal", "metadata"}
	schemeRe      = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):`)
	v4Part        = regexp.MustCompile(`^(0|[1-9]\d{0,2})$`)
	v6Part        = regexp.MustCompile(`(?i)^[0-9a-f]{1,4}$`)
	allDigits     = regexp.MustCompile(`^\d+$`)
	hexNumber     = regexp.MustCompile(`(?i)^0x[0-9a-f]+$`)
	numPart       = regexp.MustCompile(`(?i)^(0x[0-9a-f]+|\d+)$`)
	leadingZero   = regexp.MustCompile(`^0\d`)
	hexPrefix     = regexp.MustCompile(`(?i)^0x`)
)

// RawURL returns the scheme and the raw host as written (lower-cased,
// brackets stripped). ok is false when the text has no scheme.
func RawURL(u string) (scheme, host string, ok bool) {
	m := schemeRe.FindStringSubmatch(u)
	if m == nil {
		return "", "", false
	}
	scheme = strings.ToLower(m[1])
	rest := u[len(m[0]):]
	if !strings.HasPrefix(rest, "//") {
		return scheme, "", true
	}
	rest = rest[2:]
	auth := rest
	if end := strings.IndexAny(rest, "/?#\\"); end >= 0 {
		auth = rest[:end]
	}
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		auth = auth[at+1:]
	}
	host = auth
	if strings.HasPrefix(host, "[") {
		if k := strings.IndexByte(host, ']'); k >= 0 {
			host = host[1:k]
		} else {
			host = host[1:]
		}
	} else if k := strings.IndexByte(host, ':'); k >= 0 {
		host = host[:k]
	}
	return scheme, strings.ToLower(host), true
}

func parseV4(s string) []int {
	p := strings.Split(s, ".")
	if len(p) != 4 {
		return nil
	}
	out := make([]int, 4)
	for i, x := range p {
		if !v4Part.MatchString(x) {
			return nil
		}
		n, _ := strconv.Atoi(x)
		if n > 255 {
			return nil
		}
		out[i] = n
	}
	return out
}

// parseV6 returns 16 bytes, or nil.
func parseV6(s string) []int {
	if !strings.Contains(s, ":") {
		return nil
	}
	var tail []int
	str := s
	last := strings.LastIndexByte(str, ':')
	if v4 := parseV4(str[last+1:]); v4 != nil {
		tail = v4
		str = str[:last] + ":0:0"
	}
	halves := strings.Split(str, "::")
	if len(halves) > 2 {
		return nil
	}
	parse := func(h string) ([]int, bool) {
		if h == "" {
			return nil, true
		}
		var out []int
		for _, x := range strings.Split(h, ":") {
			if !v6Part.MatchString(x) {
				return nil, false
			}
			n, _ := strconv.ParseUint(x, 16, 32)
			out = append(out, int(n))
		}
		return out, true
	}
	a, ok := parse(halves[0])
	if !ok {
		return nil
	}
	var b []int
	if len(halves) == 2 {
		if b, ok = parse(halves[1]); !ok {
			return nil
		}
	}
	fill := 0
	if len(halves) == 2 {
		fill = 8 - len(a) - len(b)
	}
	if fill < 0 || (len(halves) == 1 && len(a) != 8) {
		return nil
	}
	words := append(append(append([]int{}, a...), make([]int, fill)...), b...)
	bytes := make([]int, 0, 16)
	for _, w := range words {
		bytes = append(bytes, w>>8, w&255)
	}
	if len(tail) > 0 && len(bytes) >= 16 {
		copy(bytes[12:16], tail)
	}
	return bytes
}

func v4Private(b []int) bool {
	a, c := b[0], b[1]
	return a == 0 || a == 10 || a == 127 || (a == 100 && c >= 64 && c < 128) || (a == 169 && c == 254) ||
		(a == 172 && c >= 16 && c < 32) || (a == 192 && c == 168) || (a == 198 && (c == 18 || c == 19))
}

func allZero(b []int) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// IsPrivateAddress reports whether an address is private, loopback,
// link-local or unique-local, IPv4-mapped/compatible IPv6 decoded first.
func IsPrivateAddress(addr string) bool {
	a := strings.ToLower(addr)
	a = strings.TrimPrefix(a, "[")
	a = strings.TrimSuffix(a, "]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	if v4 := parseV4(a); v4 != nil {
		return v4Private(v4)
	}
	v6 := parseV6(a)
	if len(v6) != 16 {
		return false
	}
	zero10 := allZero(v6[:10])
	if zero10 && v6[10] == 0xff && v6[11] == 0xff {
		return v4Private(v6[12:])
	}
	zero12 := zero10 && v6[10] == 0 && v6[11] == 0
	loopOrAny := allZero(v6[12:15]) && v6[15] <= 1
	if zero12 && !loopOrAny {
		return v4Private(v6[12:])
	}
	if allZero(v6) {
		return true
	}
	if allZero(v6[:15]) && v6[15] == 1 {
		return true
	}
	if v6[0]&0xfe == 0xfc {
		return true
	}
	return v6[0] == 0xfe && v6[1]&0xc0 == 0x80
}

// IsIPLiteral reports whether host is an IPv4 or IPv6 literal.
func IsIPLiteral(host string) bool { return parseV4(host) != nil || parseV6(host) != nil }

func isObfuscatedV4(host string) bool {
	if host == "" || parseV4(host) != nil {
		return false
	}
	if allDigits.MatchString(host) || hexNumber.MatchString(host) {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 || len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !numPart.MatchString(p) {
			return false
		}
	}
	if len(parts) < 4 {
		return true
	}
	for _, p := range parts {
		if leadingZero.MatchString(p) || hexPrefix.MatchString(p) {
			return true
		}
	}
	return false
}

// HostMatches reports whether host matches an allow-list entry (host or
// *.suffix).
func HostMatches(host, pattern string) bool {
	p := strings.ToLower(pattern)
	if strings.HasPrefix(p, "*.") {
		return strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1
	}
	return host == p
}

// taintOf returns the input that taints the URL's host, if any.
func taintOf(u, host string, inputs []Input) *Input {
	if host != "" {
		hostEnd := strings.Index(strings.ToLower(u), host) + len(host)
		for i := range inputs {
			v := inputs[i].Value
			if charLen(v) < 3 {
				continue
			}
			if strings.Contains(strings.ToLower(v), host) || (strings.HasPrefix(u, v) && len(v) >= hostEnd) {
				return &inputs[i]
			}
		}
		return nil
	}
	// No host (file:, gopher: without //): an input that is a prefix past the scheme.
	schemeEnd := strings.IndexByte(u, ':') + 1
	for i := range inputs {
		v := inputs[i].Value
		if charLen(v) >= 3 && strings.HasPrefix(u, v) && len(v) > schemeEnd {
			return &inputs[i]
		}
	}
	return nil
}

func isMetadata(h string) bool {
	for _, m := range MetadataHosts {
		if h == m {
			return true
		}
	}
	return false
}

// DetectSSRF runs the ssrf rules on a URL; resolved are the addresses the
// connection uses (empty when not known).
func DetectSSRF(u string, inputs []Input, resolved []string) *Finding {
	return detectSSRFWith(u, inputs, resolved, nil)
}

func detectSSRFWith(u string, inputs []Input, resolved []string, slot *iastSlot) *Finding {
	scheme, host, ok := RawURL(u)
	if !ok {
		return nil
	}
	inp := taintOf(u, host, inputs)
	if inp == nil {
		return nil
	}
	if ssrfProtocols[scheme] {
		return found(SSRF, "ssrf.protocol", inp)
	}
	meta := isMetadata(host)
	for _, a := range resolved {
		meta = meta || isMetadata(strings.ToLower(a))
	}
	if meta {
		return found(SSRF, "ssrf.metadata", inp)
	}
	if isObfuscatedV4(host) {
		return found(SSRF, "ssrf.obfuscated", inp)
	}
	internal := host == "localhost" || strings.HasSuffix(host, ".localhost") || (IsIPLiteral(host) && IsPrivateAddress(host))
	for _, a := range resolved {
		internal = internal || IsPrivateAddress(a)
	}
	if internal {
		return found(SSRF, "ssrf.internal", inp)
	}
	dns := dnslogHosts[host]
	for _, s := range dnslogSuffixes {
		dns = dns || strings.HasSuffix(host, s)
	}
	if dns {
		return found(SSRF, "ssrf.dnslog", inp)
	}
	slot.note(func() *vuln { return vulnSSRF(u, host, inputs) }) // passive IAST
	return nil
}

// DetectOutbound runs outbound.not_allowed: the host matches none of the
// allow-list (alwaysAllowed hosts aside). An empty allow-list checks nothing.
func DetectOutbound(u string, allow, alwaysAllowed []string) *Finding {
	if len(allow) == 0 {
		return nil
	}
	_, host, ok := RawURL(u)
	if !ok || host == "" {
		return nil
	}
	for _, h := range alwaysAllowed {
		if h == host {
			return nil
		}
	}
	for _, p := range allow {
		if HostMatches(host, p) {
			return nil
		}
	}
	return &Finding{Attack: Outbound, Rule: "outbound.not_allowed", Target: host}
}

// ---- Deserialization, code, XML, XSS ------------------------------------------

var base64ish = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)

// lenientBase64 decodes as Node's Buffer.from(s, "base64") does for the
// alphabet base64ish allows: both alphabets, decoding stops at the first =,
// a dangling sixth bit group is dropped.
func lenientBase64(s string) []byte {
	if i := strings.IndexByte(s, '='); i >= 0 {
		s = s[:i]
	}
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	if len(s)%4 == 1 {
		s = s[:len(s)-1]
	}
	out, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

// TaintedData returns the input that taints data: equal to it, containing
// it, or (length >= 8) contained in it; base64-decoded inputs count too.
// Data is compared as bytes.
func TaintedData(data string, inputs []Input) *Input {
	if data == "" {
		return nil
	}
	for i := range inputs {
		v := inputs[i].Value
		if v == "" {
			continue
		}
		if v == data || strings.Contains(v, data) || (charLen(v) >= 8 && strings.Contains(data, v)) {
			return &inputs[i]
		}
		if charLen(v) >= 8 && base64ish.MatchString(v) {
			dec := string(lenientBase64(v))
			if dec != "" && (dec == data || (len(dec) >= 8 && (strings.Contains(dec, data) || strings.Contains(data, dec)))) {
				return &inputs[i]
			}
		}
	}
	return nil
}

// DeserFormat names a deserialization format of the contract.
type DeserFormat string

// The deserialization formats of the contract.
const (
	DeserPickle          DeserFormat = "pickle"
	DeserMarshal         DeserFormat = "marshal"
	DeserYAML            DeserFormat = "yaml"
	DeserJSONPickle      DeserFormat = "jsonpickle"
	DeserNodeSerialize   DeserFormat = "node_serialize"
	DeserFuncster        DeserFormat = "funcster"
	DeserBinaryFormatter DeserFormat = "binaryformatter"
	DeserTypeName        DeserFormat = "typename"
	DeserJava            DeserFormat = "java"
	DeserSnakeYAML       DeserFormat = "snakeyaml"
)

var jsonpickleMarks = []string{`"py/reduce"`, `"py/object"`, `"py/type"`, `"py/function"`, `"py/repr"`, `"py/newargs"`}

// snakeyamlClassTag is a SnakeYAML global tag naming a Java class (`!!` or
// `!<tag:yaml.org,2002:` followed by a dotted name). Standard tags such as
// `!!str` have no dot and never match.
var snakeyamlClassTag = regexp.MustCompile(`(?:^|[\s\[{,])(?:!!|!<tag:yaml\.org,2002:)[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$]`)

// DetectDeserialization runs the deser.* rule of a format on tainted data.
func DetectDeserialization(format DeserFormat, data string, inputs []Input) *Finding {
	return detectDeserializationWith(format, data, inputs, nil)
}

func detectDeserializationWith(format DeserFormat, data string, inputs []Input, slot *iastSlot) *Finding {
	inp := TaintedData(data, inputs)
	if inp == nil {
		return nil
	}
	// Passive IAST: tainted data reaching an unsafe deserializer, whatever
	// the format check says.
	slot.note(func() *vuln { return vulnData("vuln.deser_input", data, TaintedData(data, requestOnly(inputs))) })
	hit := func(rule string) *Finding { return found(Deserialization, rule, inp) }
	switch format {
	case DeserPickle:
		return hit("deser.pickle")
	case DeserMarshal:
		return hit("deser.marshal")
	case DeserBinaryFormatter:
		return hit("deser.binaryformatter")
	case DeserJava:
		return hit("deser.java")
	case DeserSnakeYAML:
		if snakeyamlClassTag.MatchString(data) {
			return hit("deser.yaml")
		}
	case DeserYAML:
		if strings.Contains(data, "!!python/") || strings.Contains(data, "!!js/") {
			return hit("deser.yaml")
		}
	case DeserJSONPickle:
		for _, m := range jsonpickleMarks {
			if strings.Contains(data, m) {
				return hit("deser.jsonpickle")
			}
		}
	case DeserNodeSerialize:
		if strings.Contains(data, "_$$ND_FUNC$$_") {
			return hit("deser.node_serialize")
		}
	case DeserFuncster:
		if strings.Contains(data, "__js_function") {
			return hit("deser.funcster")
		}
	case DeserTypeName:
		if strings.Contains(data, `"$type"`) || strings.Contains(data, `"__type"`) {
			return hit("deser.typename")
		}
	}
	return nil
}

// DetectCode runs code.eval: a tainted input of length >= 3 spanning >= 2
// tokens of the generic lexer, or equal to the code.
func DetectCode(code string, inputs []Input) *Finding {
	return detectCodeWith(code, inputs, nil)
}

func detectCodeWith(code string, inputs []Input, slot *iastSlot) *Finding {
	if code == "" {
		return nil
	}
	var tokens []Token
	lexed := false
	for i := range inputs {
		v := inputs[i].Value
		if charLen(v) < 3 {
			continue
		}
		if v == code {
			return found(CodeInjection, "code.eval", &inputs[i])
		}
		for _, idx := range Occurrences(code, v, 8) {
			if !lexed {
				tokens, lexed = CodeTokens(code), true
			}
			if countOverlapping(tokens, idx, len(v)) >= 2 {
				return found(CodeInjection, "code.eval", &inputs[i])
			}
		}
	}
	slot.note(func() *vuln { // passive IAST
		return vulnCode(code, inputs, func() []Token {
			if !lexed {
				tokens, lexed = CodeTokens(code), true
			}
			return tokens
		})
	})
	return nil
}

type entityDecl struct {
	name     string
	external bool
	uri      string
	value    string
}

var (
	doctypeExt   = regexp.MustCompile(`[` + jsSpaceClass + `](SYSTEM|PUBLIC)[` + jsSpaceClass + `]`)
	quotedLit    = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	entityBody   = regexp.MustCompile(`(?s)^(%[` + jsSpaceClass + `]+)?([^` + jsSpaceClass + `]+)[` + jsSpaceClass + `]+(.*)$`)
	externalKw   = regexp.MustCompile(`^(SYSTEM|PUBLIC)\b`)
	uriScheme    = regexp.MustCompile(`(?i)^([a-z][a-z0-9+.-]*):`)
	fileURL      = regexp.MustCompile(`(?i)^file:(//)?`)
	schemaFile   = regexp.MustCompile(`(?i)\.(dtd|xsd|xml)$`)
	entityRef    = regexp.MustCompile(`[&%][^` + jsSpaceClass + `;]+;`)
	xxeProtocols = wordSet("ftp dict gopher netdoc mailto jar php expect")
)

func unquoteLit(l string) string {
	if len(l) >= 2 {
		return l[1 : len(l)-1]
	}
	return ""
}

func parseDoctype(xml string) (hasDoctype bool, externalDtd *string, entities []entityDecl) {
	at := strings.Index(xml, "<!DOCTYPE")
	if at < 0 {
		return false, nil, nil
	}
	head := xml[at:]
	if len(head) > 64*1024 {
		head = head[:64*1024]
	}
	bracket := strings.IndexByte(head, '[')
	closeAt := strings.IndexByte(head, '>')
	end := closeAt
	if bracket >= 0 && bracket < closeAt {
		end = bracket
	}
	decl := head
	if end >= 0 {
		decl = head[:end]
	} else {
		// TypeScript's slice(0, -1) drops the last character.
		decl = head[:max(0, len(head)-1)]
	}
	if loc := doctypeExt.FindStringSubmatchIndex(decl); loc != nil {
		kw := decl[loc[2]:loc[3]]
		lits := quotedLit.FindAllString(decl[loc[0]:], -1)
		pick := ""
		if kw == "PUBLIC" && len(lits) > 1 {
			pick = lits[1]
		} else if len(lits) > 0 {
			pick = lits[0]
		}
		dtd := unquoteLit(pick)
		externalDtd = &dtd
	}
	from := 0
	for len(entities) < 1000 {
		k := strings.Index(head[from:], "<!ENTITY")
		if k < 0 {
			break
		}
		i := from + k
		endAt := strings.IndexByte(head[i:], '>')
		var body string
		if endAt < 0 {
			body = head[i+8:]
			from = len(head)
		} else {
			body = head[i+8 : i+endAt]
			from = i + endAt + 1
		}
		body = jsTrim(body)
		m := entityBody.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		rest := jsTrim(m[3])
		lits := quotedLit.FindAllString(rest, -1)
		external := externalKw.MatchString(rest)
		e := entityDecl{name: m[2], external: external}
		if external {
			idx := 0
			if strings.HasPrefix(rest, "PUBLIC") {
				idx = 1
			}
			if idx < len(lits) {
				e.uri = unquoteLit(lits[idx])
			}
		} else if len(lits) > 0 {
			e.value = unquoteLit(lits[0])
		}
		entities = append(entities, e)
	}
	return true, externalDtd, entities
}

// DetectXML runs the xxe rules on tainted XML; resolvesExternal says whether
// the parser resolves external entities.
func DetectXML(xml string, inputs []Input, resolvesExternal bool) *Finding {
	return detectXMLWith(xml, inputs, resolvesExternal, nil)
}

func detectXMLWith(xml string, inputs []Input, resolvesExternal bool, slot *iastSlot) *Finding {
	// Passive IAST: request data parsed by a parser that resolves external
	// entities, DOCTYPE or not.
	if xml != "" && resolvesExternal {
		slot.note(func() *vuln { return vulnData("vuln.xml_external", xml, TaintedData(xml, requestOnly(inputs))) })
	}
	if xml == "" || !strings.Contains(xml, "<!DOCTYPE") {
		return nil
	}
	inp := TaintedData(xml, inputs)
	if inp == nil {
		return nil
	}
	_, dtd, entities := parseDoctype(xml)
	var uris []string
	for _, e := range entities {
		if e.external {
			uris = append(uris, e.uri)
		}
	}
	if dtd != nil {
		uris = append(uris, *dtd)
	}
	for _, u := range uris {
		scheme := ""
		if m := uriScheme.FindStringSubmatch(u); m != nil {
			scheme = strings.ToLower(m[1])
		}
		if (scheme != "" && xxeProtocols[scheme]) || strings.HasPrefix(u, `\\`) {
			return found(XXE, "xxe.protocol", inp)
		}
		if scheme == "file" {
			p := fileURL.ReplaceAllString(u, "")
			if (strings.HasPrefix(p, "/") || driveOnly.MatchString(p) || strings.Contains(p, "../")) && !schemaFile.MatchString(p) {
				return found(XXE, "xxe.file", inp)
			}
		}
	}
	if len(uris) > 0 {
		if resolvesExternal {
			return found(XXE, "xxe.external_entity", inp)
		}
		return found(XXE, "xxe.doctype", inp)
	}
	referencing := 0
	for _, e := range entities {
		if !e.external && entityRef.MatchString(e.value) {
			referencing++
		}
	}
	if referencing >= 3 {
		return found(XXE, "xxe.billion_laughs", inp)
	}
	return nil
}

// The contract's tag pattern (OpenRASP xss_userinput) includes control
// characters on purpose.
var (
	xssTag     = regexp.MustCompile(`<![\-\[A-Za-z]|<([A-Za-z]{1,12})[/>\x00-\x20]`)
	xssHandler = regexp.MustCompile(`(?i)\bon[a-z]{3,}[` + jsSpaceClass + `]*=`)
)

// MaxXSSBody is the largest response body xss.reflected checks.
const MaxXSSBody = 1024 * 1024

// DetectXSS runs xss.reflected on an HTML response body.
func DetectXSS(contentType, body string, inputs []Input) *Finding {
	if contentType == "" || !strings.Contains(strings.ToLower(contentType), "html") || body == "" || charLen(body) > MaxXSSBody {
		return nil
	}
	for i := range inputs {
		v := inputs[i].Value
		if charLen(v) < 15 {
			continue
		}
		if !(xssTag.MatchString(v) || strings.Contains(strings.ToLower(v), "javascript:") || xssHandler.MatchString(v)) {
			continue
		}
		if strings.Contains(body, v) {
			return found(XSS, "xss.reflected", &inputs[i])
		}
	}
	return nil
}

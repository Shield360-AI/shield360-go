package rasp

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Input normalization: percent-decoded forms, flattening of parsed bodies and
// model-output fragments (README "Sources of untrusted input" and
// "Implementation notes").

// The contract's limits.
const (
	MaxInputs    = 256
	MaxValue     = 4096
	MaxFragments = 32
	MaxRawBody   = 8 * 1024
	maxDepth     = 16
)

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// PercentDecode is the contract's lenient percent decoding: each %XX becomes
// a byte, other % stay, + is not a space, and the bytes are read as UTF-8
// with invalid sequences replaced by U+FFFD.
func PercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				out = append(out, h<<4|l)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return strings.ToValidUTF8(string(out), "�")
}

// addInput adds an input and, for request input holding %, its decoded and
// double-decoded forms when they differ. Caps count and length.
func addInput(list *[]Input, value, key string, source Source) {
	if value == "" || len(*list) >= MaxInputs {
		return
	}
	v := truncChars(value, MaxValue)
	*list = append(*list, Input{Value: v, Key: key, Source: source})
	if source != SourceRequest || !strings.Contains(v, "%") {
		return
	}
	once := PercentDecode(v)
	if once != v && len(*list) < MaxInputs {
		*list = append(*list, Input{Value: once, Key: key, Source: source})
		twice := PercentDecode(once)
		if twice != once && len(*list) < MaxInputs {
			*list = append(*list, Input{Value: twice, Key: key, Source: source})
		}
	}
}

// AddInput adds request input to list as the contract's normalizer does
// (percent-decoded forms added, limits applied).
func AddInput(list []Input, value, key string) []Input {
	addInput(&list, value, key, SourceRequest)
	return list
}

// flatten adds the string leaves of a parsed value (key.a.b, arrays by
// index). Map keys are visited in sorted order so the result is stable;
// JSON text keeps its own order through flattenJSON.
func flatten(list *[]Input, value any, key string, depth int) {
	if len(*list) >= MaxInputs || depth > maxDepth || value == nil {
		return
	}
	switch v := value.(type) {
	case string:
		addInput(list, v, key, SourceRequest)
		return
	case []byte, json.Number, bool, float64, float32, int, int64, int32, uint, uint64:
		return
	case []any:
		for i, x := range v {
			flatten(list, x, key+"."+strconv.Itoa(i), depth+1)
		}
		return
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flatten(list, v[k], key+"."+k, depth+1)
		}
		return
	case map[string][]string: // url.Values
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals := v[k]
			if len(vals) == 1 {
				flatten(list, vals[0], key+"."+k, depth+1)
				continue
			}
			for i, x := range vals {
				flatten(list, x, key+"."+k+"."+strconv.Itoa(i), depth+1)
			}
		}
		return
	case map[string]string:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flatten(list, v[k], key+"."+k, depth+1)
		}
		return
	}
	// Other maps, slices and structs' pointers: by reflection.
	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.String:
		addInput(list, rv.String(), key, SourceRequest)
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < rv.Len(); i++ {
			flatten(list, rv.Index(i).Interface(), key+"."+strconv.Itoa(i), depth+1)
		}
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return
		}
		keys := rv.MapKeys()
		sort.Slice(keys, func(a, b int) bool { return keys[a].String() < keys[b].String() })
		for _, k := range keys {
			flatten(list, rv.MapIndex(k).Interface(), key+"."+k.String(), depth+1)
		}
	}
}

// flattenJSON adds the string leaves of JSON text in document order.
// It returns false when the text is not valid JSON.
func flattenJSON(list *[]Input, data []byte, key string) bool {
	if !json.Valid(data) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkJSON(dec, list, key, 0)
}

// walkJSON reads one JSON value from dec, adding string leaves.
func walkJSON(dec *json.Decoder, list *[]Input, key string, depth int) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	switch t := tok.(type) {
	case string:
		if depth <= maxDepth {
			addInput(list, t, key, SourceRequest)
		}
		return true
	case json.Delim:
		switch t {
		case '{':
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return false
				}
				k, _ := kt.(string)
				if !walkJSON(dec, list, key+"."+k, depth+1) {
					return false
				}
			}
			_, err := dec.Token()
			return err == nil
		case '[':
			i := 0
			for dec.More() {
				if !walkJSON(dec, list, key+"."+strconv.Itoa(i), depth+1) {
					return false
				}
				i++
			}
			_, err := dec.Token()
			return err == nil
		}
		return false
	default:
		return true
	}
}

// ModelFragments splits model text into fragments: the content of each
// fenced code block, then each line; trimmed, empty and duplicate fragments
// dropped, at most 32 of at most 4096 characters.
func ModelFragments(text string) []string {
	var out []string
	seen := map[string]bool{}
	push := func(f string) {
		t := jsTrim(f)
		if t == "" || seen[t] || len(out) >= MaxFragments {
			return
		}
		seen[t] = true
		out = append(out, truncChars(t, MaxValue))
	}
	lines := strings.Split(text, "\n")
	var block []string
	inBlock := false
	for _, line := range lines {
		if strings.HasPrefix(jsTrim(line), "```") {
			if inBlock {
				push(strings.Join(block, "\n"))
				block, inBlock = nil, false
			} else {
				block, inBlock = []string{}, true
			}
			continue
		}
		if inBlock {
			block = append(block, line)
		}
	}
	if inBlock {
		push(strings.Join(block, "\n"))
	}
	for _, line := range lines {
		if !strings.HasPrefix(jsTrim(line), "```") {
			push(line)
		}
	}
	return out
}

// addModelOutput adds model text as model_output fragments.
func addModelOutput(list *[]Input, text, key string) {
	if key == "" {
		key = "model.completion"
	}
	for _, f := range ModelFragments(text) {
		if len(*list) >= MaxInputs {
			return
		}
		*list = append(*list, Input{Value: f, Key: key, Source: SourceModelOutput})
	}
}

// AddModelOutput adds model text to list as model_output fragments.
func AddModelOutput(list []Input, text, key string) []Input {
	addModelOutput(&list, text, key)
	return list
}

// addToolArguments adds tool-call argument string leaves as model_output
// (model.tool.<path>). A string is parsed as JSON; text that is not JSON is
// fragmented like completion text.
func addToolArguments(list *[]Input, args any, path string) {
	if path == "" {
		path = "model.tool"
	}
	var tmp []Input
	switch a := args.(type) {
	case string:
		if !flattenJSON(&tmp, []byte(a), path) {
			addModelOutput(list, a, path)
			return
		}
	case []byte:
		if !flattenJSON(&tmp, a, path) {
			addModelOutput(list, string(a), path)
			return
		}
	case json.RawMessage:
		flattenJSON(&tmp, a, path)
	default:
		flatten(&tmp, args, path, 0)
	}
	for _, i := range tmp {
		if len(*list) < MaxInputs {
			*list = append(*list, Input{Value: i.Value, Key: i.Key, Source: SourceModelOutput})
		}
	}
}

// parseCookies parses a Cookie header into name/value pairs, in order.
func parseCookies(header string) [][2]string {
	if header == "" {
		return nil
	}
	var out [][2]string
	for _, part := range strings.Split(header, ";") {
		i := strings.IndexByte(part, '=')
		if i <= 0 {
			continue
		}
		out = append(out, [2]string{jsTrim(part[:i]), jsTrim(part[i+1:])})
	}
	return out
}

// parseQuery parses a raw query string in order, as URLSearchParams does:
// & separates pairs, + is a space, and a malformed escape stays as written.
func parseQuery(raw string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		out = append(out, [2]string{formDecode(k), formDecode(v)})
	}
	return out
}

// formDecode decodes application/x-www-form-urlencoded text leniently.
func formDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	if !strings.Contains(s, "%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				out = append(out, h<<4|l)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	if utf8.Valid(out) {
		return string(out)
	}
	return strings.ToValidUTF8(string(out), "�")
}

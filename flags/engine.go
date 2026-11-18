// Package flags is the Shield360 feature-flag engine and client for Go.
//
// The engine (this file) is a faithful port of sdk/flags-core/src/engine.ts,
// the canonical engine the server and the TypeScript SDK copy byte for byte.
// Every implementation is held to sdk/flags-core/testdata/vectors.json, so
// the answers cannot drift: change the TypeScript first, port the change
// here, and add vectors.
//
// The engine works on decoded JSON: map[string]any, []any, float64, string,
// bool and nil. Values of other Go types (ints, typed slices, structs) are
// converted to that shape first, as encoding/json would see them.
//
// Pure: no I/O, no clock, no randomness. The same flag and context always
// give the same answer, and the same bucket as every other SDK.
package flags

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Flag types.
const (
	TypeBoolean = "boolean"
	TypeString  = "string"
	TypeNumber  = "number"
	TypeJSON    = "json"
)

// FlagTypes lists the flag types, in the canonical order.
var FlagTypes = []string{TypeBoolean, TypeString, TypeNumber, TypeJSON}

// Operators lists every condition operator.
var Operators = []string{
	"equals", "not_equals", "in", "not_in", "contains", "starts_with",
	"lt", "lte", "gt", "gte",
	"semver_eq", "semver_lt", "semver_lte", "semver_gt", "semver_gte",
	"in_segment", "not_in_segment",
}

// SegmentOperators are the operators whose condition names segments: the
// attribute is the literal "segment" and the values are segment keys. A
// condition naming a segment that was not passed (or does not validate)
// never holds, either way.
var SegmentOperators = []string{"in_segment", "not_in_segment"}

// SegmentAttribute is the attribute of a segment condition.
const SegmentAttribute = "segment"

// Buckets run 0..99,999: a rollout weight of 1 is a thousandth of a percent.
const Buckets = 100000

// DefaultBucketBy is the attribute a rollout buckets by when it names none.
const DefaultBucketBy = "key"

// Limits are the counts every implementation checks alike. Lengths and sizes
// are the server's to limit.
var Limits = struct {
	Variations, Rules, Conditions, ConditionValues, SegmentsPerCondition int
}{20, 50, 20, 100, 20}

// Reason kinds. The engine gives OFF, ARCHIVED, RULE_MATCH, FALLTHROUGH and
// ERROR; the client adds NOT_READY, FLAG_NOT_FOUND and WRONG_TYPE.
const (
	ReasonOff          = "OFF"
	ReasonArchived     = "ARCHIVED"
	ReasonRuleMatch    = "RULE_MATCH"
	ReasonFallthrough  = "FALLTHROUGH"
	ReasonError        = "ERROR"
	ReasonNotReady     = "NOT_READY"
	ReasonFlagNotFound = "FLAG_NOT_FOUND"
	ReasonWrongType    = "WRONG_TYPE"
)

// ErrorMalformedFlag is the ErrorKind of a flag that fails validation.
const ErrorMalformedFlag = "MALFORMED_FLAG"

var (
	reFlagKey      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	reVariationKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$`)
	reRuleID       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reAttribute    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	reSalt         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reNumberText   = regexp.MustCompile(`^-?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$`)
	reSemver       = regexp.MustCompile(`^v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	reNumericID    = regexp.MustCompile(`^[0-9]+$`)
)

// Reason says why a variation was served (or why none was).
type Reason struct {
	Kind string
	// RuleIndex and RuleID are set for RULE_MATCH.
	RuleIndex int
	RuleID    string
	// InRollout is true when a rollout picked the variation; Bucket is then
	// the bucket the context fell in.
	InRollout bool
	Bucket    int
	// ErrorKind is MALFORMED_FLAG for a flag that fails validation.
	ErrorKind string
}

// MarshalJSON writes the reason as the other SDKs do, leaving absent fields out.
func (r Reason) MarshalJSON() ([]byte, error) {
	m := map[string]any{"kind": r.Kind}
	if r.Kind == ReasonRuleMatch {
		m["ruleIndex"] = r.RuleIndex
		m["ruleId"] = r.RuleID
	}
	if r.InRollout {
		m["inRollout"] = true
		m["bucket"] = r.Bucket
	}
	if r.ErrorKind != "" {
		m["errorKind"] = r.ErrorKind
	}
	return json.Marshal(m)
}

// Evaluation is what a flag serves a context.
type Evaluation struct {
	// Variation is the served variation's key; empty only when the flag is
	// malformed (variation keys are never empty).
	Variation string
	// Value is the served variation's value (decoded JSON); nil when malformed.
	Value  any
	Reason Reason
}

// MarshalJSON writes {variation, value, reason}, with a null variation when none was served.
func (e Evaluation) MarshalJSON() ([]byte, error) {
	var variation any
	if e.Variation != "" {
		variation = e.Variation
	}
	return json.Marshal(map[string]any{"variation": variation, "value": e.Value, "reason": e.Reason})
}

// ValidationError is one thing wrong with a flag or segment.
type ValidationError struct {
	Path string `json:"path"`
	Code string `json:"code"`
}

// ------------------------------------------------------------------ helpers

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func isRecord(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

func isStringIn(v any, list []string) bool {
	s, ok := v.(string)
	return ok && contains(list, s)
}

func matches(re *regexp.Regexp, v any) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

// IsFlagKey reports whether v is a valid flag (or segment) key.
func IsFlagKey(v any) bool { return matches(reFlagKey, v) }

// IsAttributeName reports whether v is a valid attribute name.
func IsAttributeName(v any) bool { return matches(reAttribute, v) }

func isSegmentOperator(v any) bool { return isStringIn(v, SegmentOperators) }

func isFinite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// get is a property read that tells a missing key (JavaScript's undefined)
// from one present with JSON null.
func get(m map[string]any, key string) (any, bool) {
	v, ok := m[key]
	return v, ok
}

// ------------------------------------------------------------------ hashing

// utf8Bytes is the UTF-8 encoding the TypeScript engine hashes. A lone
// surrogate (WTF-8 encoded) or an invalid byte becomes U+FFFD, as
// TextEncoder writes one.
func utf8Bytes(text string) []byte {
	if utf8.ValidString(text) {
		return []byte(text)
	}
	out := make([]byte, 0, len(text)+8)
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size <= 1 {
			// A WTF-8 surrogate (ED A0..BF 80..BF) is one code unit in JavaScript.
			if i+2 < len(text) && text[i] == 0xED && text[i+1] >= 0xA0 && text[i+1] <= 0xBF &&
				text[i+2] >= 0x80 && text[i+2] <= 0xBF {
				size = 3
			} else {
				size = 1
			}
			out = utf8.AppendRune(out, utf8.RuneError)
			i += size
			continue
		}
		out = append(out, text[i:i+size]...)
		i += size
	}
	return out
}

// Murmur3 is MurmurHash3 (x86, 32-bit, seed 0) of the UTF-8 bytes of text.
func Murmur3(text string) uint32 {
	data := utf8Bytes(text)
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data)
	blocks := n - n%4
	for i := 0; i < blocks; i += 4 {
		k := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := n % 4
	if tail == 3 {
		k ^= uint32(data[blocks+2]) << 16
	}
	if tail >= 2 {
		k ^= uint32(data[blocks+1]) << 8
	}
	if tail >= 1 {
		k ^= uint32(data[blocks])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// BucketOf is the bucket (0..99,999) a value falls in for a flag: stable
// across runs, processes and SDKs.
func BucketOf(flagKey, salt, value string) int {
	return int(Murmur3(flagKey+"."+salt+"."+value) % Buckets)
}

// ----------------------------------------------------------- attribute text

// jsNumberText is ECMAScript's Number::toString for a finite number.
func jsNumberText(v float64) string {
	if v == 0 {
		return "0" // -0 too
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	// The shortest round-trip digits, as JavaScript picks them.
	s := strconv.FormatFloat(v, 'e', -1, 64) // d.ddde±XX
	mant, expText, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expText)
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1 // the value is 0.digits × 10^n
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	e := n - 1
	m := digits
	if k > 1 {
		m = digits[:1] + "." + digits[1:]
	}
	es := "+"
	if e < 0 {
		es = "-"
		e = -e
	}
	return sign + m + "e" + es + strconv.Itoa(e)
}

// TextOf is the text of a scalar, the same in every SDK: strings as they are,
// booleans as true/false, numbers as JavaScript prints them. ok is false for
// anything else (nil, non-finite numbers, lists, objects).
func TextOf(v any) (string, bool) {
	switch x := normalizeScalar(v).(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case float64:
		if !isFinite(x) {
			return "", false
		}
		return jsNumberText(x), true
	}
	return "", false
}

// NumberOf is a finite number, or the text of one (no spaces).
func NumberOf(v any) (float64, bool) {
	switch x := normalizeScalar(v).(type) {
	case float64:
		return x, isFinite(x)
	case string:
		if !reNumberText.MatchString(x) {
			return 0, false
		}
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
				return 0, false
			}
		}
		return f, isFinite(f)
	}
	return 0, false
}

type semVer struct {
	major, minor, patch float64
	pre                 []string
}

func jsNumber(digits string) float64 {
	f, _ := strconv.ParseFloat(digits, 64)
	return f
}

func parseSemver(v any) (semVer, bool) {
	s, ok := v.(string)
	if !ok {
		return semVer{}, false
	}
	m := reSemver.FindStringSubmatchIndex(s)
	if m == nil {
		return semVer{}, false
	}
	group := func(i int) (string, bool) {
		if m[2*i] < 0 {
			return "", false
		}
		return s[m[2*i]:m[2*i+1]], true
	}
	out := semVer{}
	g, _ := group(1)
	out.major = jsNumber(g)
	if g, ok := group(2); ok {
		out.minor = jsNumber(g)
	}
	if g, ok := group(3); ok {
		out.patch = jsNumber(g)
	}
	if g, ok := group(4); ok {
		out.pre = strings.Split(g, ".")
	}
	return out, true
}

func compareSemver(a, b semVer) int {
	for _, p := range [][2]float64{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	if len(a.pre) == 0 || len(b.pre) == 0 {
		if len(a.pre) == len(b.pre) {
			return 0
		}
		if len(a.pre) > 0 {
			return -1 // a pre-release comes before its release
		}
		return 1
	}
	n := min(len(a.pre), len(b.pre))
	for i := 0; i < n; i++ {
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xn, yn := reNumericID.MatchString(x), reNumericID.MatchString(y)
		if xn && yn {
			if jsNumber(x) < jsNumber(y) {
				return -1
			}
			return 1
		}
		if xn != yn {
			if xn {
				return -1
			}
			return 1
		}
		if x < y {
			return -1
		}
		return 1
	}
	if len(a.pre) == len(b.pre) {
		return 0
	}
	if len(a.pre) < len(b.pre) {
		return -1
	}
	return 1
}

// ---------------------------------------------------------------- matching

func scalarMatches(op string, actual any, values []any) bool {
	switch op {
	case "equals", "in":
		text, ok := TextOf(actual)
		if !ok {
			return false
		}
		for _, v := range values {
			if t, ok := TextOf(v); ok && t == text {
				return true
			}
		}
		return false
	case "contains", "starts_with":
		text, ok := TextOf(actual)
		if !ok {
			return false
		}
		for _, v := range values {
			want, ok := TextOf(v)
			if !ok {
				continue
			}
			if op == "contains" && strings.Contains(text, want) {
				return true
			}
			if op == "starts_with" && strings.HasPrefix(text, want) {
				return true
			}
		}
		return false
	case "lt", "lte", "gt", "gte":
		n, ok := NumberOf(actual)
		if !ok {
			return false
		}
		for _, v := range values {
			w, ok := NumberOf(v)
			if !ok {
				continue
			}
			if (op == "lt" && n < w) || (op == "lte" && n <= w) || (op == "gt" && n > w) || (op == "gte" && n >= w) {
				return true
			}
		}
		return false
	case "semver_eq", "semver_lt", "semver_lte", "semver_gt", "semver_gte":
		a, ok := parseSemver(actual)
		if !ok {
			return false
		}
		for _, v := range values {
			b, ok := parseSemver(v)
			if !ok {
				continue
			}
			c := compareSemver(a, b)
			if (op == "semver_eq" && c == 0) || (op == "semver_lt" && c < 0) || (op == "semver_lte" && c <= 0) ||
				(op == "semver_gt" && c > 0) || (op == "semver_gte" && c >= 0) {
				return true
			}
		}
		return false
	}
	return false
}

var negated = map[string]string{"not_equals": "equals", "not_in": "in"}

// conditionMatches: a missing (or null) attribute never matches, negated
// operators included. A list attribute matches a positive operator when any
// item does, and a negated one when none does.
func conditionMatches(c map[string]any, ctx map[string]any, segments []any) bool {
	op, _ := c["operator"].(string)
	values, _ := c["values"].([]any)
	if isSegmentOperator(op) {
		return segmentConditionMatches(op, values, ctx, segments)
	}
	attr, _ := c["attribute"].(string)
	actual, ok := ctx[attr]
	if !ok || actual == nil {
		return false
	}
	items, isList := actual.([]any)
	if !isList {
		items = []any{actual}
	}
	if len(items) == 0 {
		return false
	}
	if positive, ok := negated[op]; ok {
		for _, item := range items {
			if scalarMatches(positive, item, values) {
				return false
			}
		}
		return true
	}
	for _, item := range items {
		if scalarMatches(op, item, values) {
			return true
		}
	}
	return false
}

// findSegment is the valid segment of this key among segments, or nil.
func findSegment(segments []any, key any) map[string]any {
	k, ok := key.(string)
	if !ok {
		return nil
	}
	for _, s := range segments {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if mk, ok := m["key"].(string); ok && mk == k {
			if len(ValidateSegment(m)) > 0 {
				return nil
			}
			return m
		}
	}
	return nil
}

// segmentMatches: the context is in the segment when every condition holds.
func segmentMatches(segment map[string]any, ctx map[string]any) bool {
	conditions, _ := segment["conditions"].([]any)
	if len(conditions) == 0 {
		return false
	}
	for _, c := range conditions {
		cm, _ := c.(map[string]any)
		if cm == nil || isSegmentOperator(cm["operator"]) || !conditionMatches(cm, ctx, nil) {
			return false
		}
	}
	return true
}

func segmentConditionMatches(op string, keys []any, ctx map[string]any, segments []any) bool {
	inAny := false
	for _, key := range keys {
		segment := findSegment(segments, key)
		if segment == nil {
			return false // an unknown segment never matches, either way
		}
		if segmentMatches(segment, ctx) {
			inAny = true
		}
	}
	if op == "in_segment" {
		return inAny
	}
	return !inAny
}

func ruleMatches(rule map[string]any, ctx map[string]any, segments []any) bool {
	conditions, _ := rule["conditions"].([]any)
	if len(conditions) == 0 {
		return false
	}
	for _, c := range conditions {
		cm, _ := c.(map[string]any)
		if cm == nil || !conditionMatches(cm, ctx, segments) {
			return false
		}
	}
	return true
}

// SegmentKeysOf lists the segment keys a flag's rules name, each once, in
// order of first use.
func SegmentKeysOf(flag any) []string {
	keys := []string{}
	f, _ := normalize(flag).(map[string]any)
	rules, _ := f["rules"].([]any)
	for _, r := range rules {
		rm, _ := r.(map[string]any)
		conditions, _ := rm["conditions"].([]any)
		for _, c := range conditions {
			cm, _ := c.(map[string]any)
			if cm == nil || !isSegmentOperator(cm["operator"]) {
				continue
			}
			values, _ := cm["values"].([]any)
			for _, v := range values {
				if s, ok := v.(string); ok && !contains(keys, s) {
					keys = append(keys, s)
				}
			}
		}
	}
	return keys
}

func rolloutVariation(flag map[string]any, rollout map[string]any, ctx map[string]any) (string, int) {
	by, _ := rollout["bucketBy"].(string)
	if by == "" {
		by = DefaultBucketBy
	}
	bucket := 0 // without the attribute everyone is bucket 0: the first variation with weight
	if text, ok := TextOf(ctx[by]); ok {
		key, _ := flag["key"].(string)
		salt, _ := flag["salt"].(string)
		bucket = BucketOf(key, salt, text)
	}
	weights, _ := rollout["weights"].([]any)
	upper := 0.0
	last := ""
	for _, w := range weights {
		wm, _ := w.(map[string]any)
		weight, _ := wm["weight"].(float64)
		variation, _ := wm["variation"].(string)
		last = variation
		upper += weight
		if float64(bucket) < upper {
			return variation, bucket
		}
	}
	// Weights are validated to sum to Buckets; this is unreachable for a valid flag.
	return last, bucket
}

// -------------------------------------------------------------- validation

// ValueMatchesType reports whether value (decoded JSON) is of the flag type.
func ValueMatchesType(flagType string, value any) bool {
	return valueMatchesType(flagType, normalize(value), true)
}

func valueMatchesType(flagType string, value any, present bool) bool {
	switch flagType {
	case TypeBoolean:
		_, ok := value.(bool)
		return ok
	case TypeString:
		_, ok := value.(string)
		return ok
	case TypeNumber:
		f, ok := value.(float64)
		return ok && isFinite(f)
	case TypeJSON:
		return present && plainJSON(value, 0)
	}
	return false
}

// plainJSON: null, a string, a boolean, a finite number, or arrays and
// objects of them, at most 20 deep.
func plainJSON(v any, depth int) bool {
	if depth > 20 {
		return false
	}
	switch x := v.(type) {
	case nil, string, bool:
		return true
	case float64:
		return isFinite(x)
	case []any:
		for _, item := range x {
			if !plainJSON(item, depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, item := range x {
			if !plainJSON(item, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// jsString is JavaScript's String(v) for the values validation inspects.
func jsString(v any, present bool) string {
	if !present {
		return "undefined"
	}
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case float64:
		switch {
		case math.IsNaN(x):
			return "NaN"
		case math.IsInf(x, 1):
			return "Infinity"
		case math.IsInf(x, -1):
			return "-Infinity"
		}
		return jsNumberText(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			if item != nil {
				parts[i] = jsString(item, true)
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

func isInteger(f float64) bool { return isFinite(f) && f == math.Trunc(f) }

func validateServe(serve any, present bool, path string, variationKeys []string, errs *[]ValidationError) {
	add := func(p, code string) { *errs = append(*errs, ValidationError{p, code}) }
	s, ok := serve.(map[string]any)
	if !present || !ok {
		add(path, "serve_invalid")
		return
	}
	variation, hasVariation := get(s, "variation")
	rolloutValue, hasRollout := get(s, "rollout")
	if hasVariation == hasRollout {
		add(path, "serve_invalid")
		return
	}
	if hasVariation {
		if !isStringIn(variation, variationKeys) {
			add(path+".variation", "variation_unknown")
		}
		return
	}
	rollout, ok := rolloutValue.(map[string]any)
	var weights []any
	if ok {
		weights, ok = rollout["weights"].([]any)
	}
	if !ok || len(weights) == 0 {
		add(path+".rollout", "rollout_invalid")
		return
	}
	if bucketBy, ok := get(rollout, "bucketBy"); ok && !IsAttributeName(bucketBy) {
		add(path+".rollout.bucketBy", "attribute_invalid")
	}
	if len(weights) > Limits.Variations {
		add(path+".rollout.weights", "too_many")
	}
	total := 0.0
	seen := []string{}
	for i, w := range weights {
		at := path + ".rollout.weights." + strconv.Itoa(i)
		wm, ok := w.(map[string]any)
		if !ok {
			add(at, "rollout_invalid")
			continue
		}
		variation := wm["variation"]
		if !isStringIn(variation, variationKeys) {
			add(at+".variation", "variation_unknown")
		} else if contains(seen, variation.(string)) {
			add(at+".variation", "duplicate")
		} else {
			seen = append(seen, variation.(string))
		}
		weight, ok := wm["weight"].(float64)
		if !ok || !isInteger(weight) || weight < 0 || weight > Buckets {
			add(at+".weight", "weight_invalid")
		} else {
			total += weight
		}
	}
	if total != Buckets {
		add(path+".rollout.weights", "weights_sum")
	}
}

func validateCondition(c any, path string, errs *[]ValidationError, inSegment bool) {
	add := func(p, code string) { *errs = append(*errs, ValidationError{p, code}) }
	cm, ok := c.(map[string]any)
	if !ok {
		add(path, "condition_invalid")
		return
	}
	operator, hasOperator := get(cm, "operator")
	if isSegmentOperator(operator) {
		if inSegment {
			add(path+".operator", "segment_nested")
			return
		}
		if attr, ok := cm["attribute"].(string); !ok || attr != SegmentAttribute {
			add(path+".attribute", "attribute_invalid")
		}
		keys, ok := cm["values"].([]any)
		if !ok || len(keys) == 0 || len(keys) > Limits.SegmentsPerCondition {
			add(path+".values", "values_invalid")
			return
		}
		seen := []string{}
		for i, v := range keys {
			at := path + ".values." + strconv.Itoa(i)
			if !IsFlagKey(v) {
				add(at, "value_not_segment")
			} else if contains(seen, v.(string)) {
				add(at, "duplicate")
			} else {
				seen = append(seen, v.(string))
			}
		}
		return
	}
	if !IsAttributeName(cm["attribute"]) {
		add(path+".attribute", "attribute_invalid")
	}
	if !isStringIn(operator, Operators) {
		add(path+".operator", "operator_invalid")
	}
	values, ok := cm["values"].([]any)
	if !ok || len(values) == 0 || len(values) > Limits.ConditionValues {
		add(path+".values", "values_invalid")
		return
	}
	if opText, ok := operator.(string); ok && (opText == "equals" || opText == "not_equals") && len(values) != 1 {
		add(path+".values", "values_invalid")
	}
	op := jsString(operator, hasOperator)
	for i, v := range values {
		at := path + ".values." + strconv.Itoa(i)
		scalar := false
		switch x := v.(type) {
		case string, bool:
			scalar = true
		case float64:
			scalar = isFinite(x)
		}
		if !scalar {
			add(at, "value_invalid")
			continue
		}
		if op == "lt" || op == "lte" || op == "gt" || op == "gte" {
			if _, ok := NumberOf(v); !ok {
				add(at, "value_not_number")
			}
		}
		if strings.HasPrefix(op, "semver_") {
			if _, ok := parseSemver(v); !ok {
				add(at, "value_not_semver")
			}
		}
	}
}

// ValidateFlag lists everything wrong with a flag definition, by path; it is
// empty (not nil) when the flag is valid. The server refuses to save an
// invalid flag; the SDKs treat one as malformed and serve the caller's default.
func ValidateFlag(flag any) []ValidationError {
	return validateFlag(normalize(flag))
}

func validateFlag(input any) []ValidationError {
	errs := []ValidationError{}
	add := func(p, code string) { errs = append(errs, ValidationError{p, code}) }
	f, ok := input.(map[string]any)
	if !ok {
		return []ValidationError{{"", "flag_invalid"}}
	}
	if !IsFlagKey(f["key"]) {
		add("key", "key_invalid")
	}
	flagType, _ := f["type"].(string)
	knownType := isStringIn(f["type"], FlagTypes)
	if !knownType {
		add("type", "type_invalid")
	}
	if _, ok := f["on"].(bool); !ok {
		add("on", "on_invalid")
	}
	if !matches(reSalt, f["salt"]) {
		add("salt", "salt_invalid")
	}
	if archived, ok := get(f, "archived"); ok {
		if _, isBool := archived.(bool); !isBool {
			add("archived", "archived_invalid")
		}
	}

	keys := []string{}
	variations, ok := f["variations"].([]any)
	if !ok || len(variations) < 2 || len(variations) > Limits.Variations {
		add("variations", "variations_count")
	} else {
		for i, v := range variations {
			at := "variations." + strconv.Itoa(i)
			vm, ok := v.(map[string]any)
			if !ok {
				add(at, "variation_invalid")
				continue
			}
			key := vm["key"]
			if !matches(reVariationKey, key) {
				add(at+".key", "variation_key_invalid")
			} else if contains(keys, key.(string)) {
				add(at+".key", "duplicate")
			} else {
				keys = append(keys, key.(string))
			}
			if name, ok := get(vm, "name"); ok {
				if _, isString := name.(string); !isString {
					add(at+".name", "name_invalid")
				}
			}
			value, present := get(vm, "value")
			if knownType && !valueMatchesType(flagType, value, present) {
				add(at+".value", "value_type")
			}
		}
		variationErrors := false
		for _, e := range errs {
			if strings.HasPrefix(e.Path, "variations") {
				variationErrors = true
			}
		}
		if knownType && flagType == TypeBoolean && !variationErrors {
			a := variations[0].(map[string]any)["value"]
			b := variations[1].(map[string]any)["value"]
			if len(variations) != 2 || a == b {
				add("variations", "boolean_variations")
			}
		}
	}

	if !isStringIn(f["offVariation"], keys) {
		add("offVariation", "variation_unknown")
	}

	rules, ok := f["rules"].([]any)
	if !ok || len(rules) > Limits.Rules {
		add("rules", "rules_invalid")
	} else {
		ids := []string{}
		for i, r := range rules {
			at := "rules." + strconv.Itoa(i)
			rm, ok := r.(map[string]any)
			if !ok {
				add(at, "rule_invalid")
				continue
			}
			id := rm["id"]
			if !matches(reRuleID, id) {
				add(at+".id", "rule_id_invalid")
			} else if contains(ids, id.(string)) {
				add(at+".id", "duplicate")
			} else {
				ids = append(ids, id.(string))
			}
			if description, ok := get(rm, "description"); ok {
				if _, isString := description.(string); !isString {
					add(at+".description", "description_invalid")
				}
			}
			conditions, ok := rm["conditions"].([]any)
			if !ok || len(conditions) == 0 || len(conditions) > Limits.Conditions {
				add(at+".conditions", "conditions_count")
			} else {
				for j, c := range conditions {
					validateCondition(c, at+".conditions."+strconv.Itoa(j), &errs, false)
				}
			}
			serve, present := get(rm, "serve")
			validateServe(serve, present, at+".serve", keys, &errs)
		}
	}
	fallthroughServe, present := get(f, "fallthrough")
	validateServe(fallthroughServe, present, "fallthrough", keys, &errs)
	return errs
}

// ValidateSegment lists everything wrong with a segment, by path; empty (not
// nil) when it is valid. A segment has a key (the flag key pattern) and 1..20
// conditions with a rule's operators, except the segment operators: segments
// do not nest.
func ValidateSegment(segment any) []ValidationError {
	s, ok := normalize(segment).(map[string]any)
	if !ok {
		return []ValidationError{{"", "segment_invalid"}}
	}
	errs := []ValidationError{}
	if !IsFlagKey(s["key"]) {
		errs = append(errs, ValidationError{"key", "key_invalid"})
	}
	conditions, ok := s["conditions"].([]any)
	if !ok || len(conditions) == 0 || len(conditions) > Limits.Conditions {
		errs = append(errs, ValidationError{"conditions", "conditions_count"})
	} else {
		for j, c := range conditions {
			validateCondition(c, "conditions."+strconv.Itoa(j), &errs, true)
		}
	}
	return errs
}

// -------------------------------------------------------------- evaluation

func malformed() Evaluation {
	return Evaluation{Reason: Reason{Kind: ReasonError, ErrorKind: ErrorMalformedFlag}}
}

// Evaluate gives the variation a flag serves a context. segments are the
// environment's segments, for rules that name them (nil for none).
//
//	archived -> the off variation (ARCHIVED)
//	off      -> the off variation (OFF)
//	on       -> the first rule, in order, whose conditions all hold
//	            (RULE_MATCH), else the fallthrough (FALLTHROUGH)
//
// A rollout picks by bucket. A malformed flag serves nothing (ERROR with
// MALFORMED_FLAG): the caller's default applies. Never panics.
//
// flag and segments are decoded JSON (map[string]any, []any) or any value
// that marshals to it; context values may be any JSON-like Go value.
func Evaluate(flag any, context map[string]any, segments any) Evaluation {
	ctx, _ := normalize(context).(map[string]any)
	segs, _ := normalize(segments).([]any)
	return evaluate(normalize(flag), ctx, segs)
}

// evaluate works on values that are already decoded JSON.
func evaluate(input any, ctx map[string]any, segments []any) (result Evaluation) {
	defer func() {
		if recover() != nil {
			result = malformed()
		}
	}()
	if len(validateFlag(input)) > 0 {
		return malformed()
	}
	flag := input.(map[string]any)
	if ctx == nil {
		ctx = map[string]any{}
	}
	variations := flag["variations"].([]any)
	served := func(key string, reason Reason) Evaluation {
		for _, v := range variations {
			vm := v.(map[string]any)
			if vm["key"] == key {
				return Evaluation{Variation: key, Value: vm["value"], Reason: reason}
			}
		}
		return malformed() // unreachable for a valid flag
	}
	offVariation := flag["offVariation"].(string)
	if archived, _ := flag["archived"].(bool); archived {
		return served(offVariation, Reason{Kind: ReasonArchived})
	}
	if on, _ := flag["on"].(bool); !on {
		return served(offVariation, Reason{Kind: ReasonOff})
	}
	serve := func(s map[string]any, reason Reason) Evaluation {
		if fixed, ok := get(s, "variation"); ok {
			return served(fixed.(string), reason)
		}
		variation, bucket := rolloutVariation(flag, s["rollout"].(map[string]any), ctx)
		reason.InRollout = true
		reason.Bucket = bucket
		return served(variation, reason)
	}
	for i, r := range flag["rules"].([]any) {
		rule := r.(map[string]any)
		if ruleMatches(rule, ctx, segments) {
			return serve(rule["serve"].(map[string]any), Reason{Kind: ReasonRuleMatch, RuleIndex: i, RuleID: rule["id"].(string)})
		}
	}
	return serve(flag["fallthrough"].(map[string]any), Reason{Kind: ReasonFallthrough})
}

// ------------------------------------------------------------ normalizing

// normalizeScalar turns any Go number into float64; other values pass through.
func normalizeScalar(v any) any {
	switch x := v.(type) {
	case nil, string, bool, float64:
		return v
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int8:
		return float64(x)
	case int16:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case uint:
		return float64(x)
	case uint8:
		return float64(x)
	case uint16:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f
		}
		return string(x)
	}
	return v
}

// normalize converts a Go value to decoded JSON: map[string]any, []any,
// float64, string, bool or nil. Already-decoded values are reused where they
// need no change; non-finite floats are kept (validation rejects them).
func normalize(v any) any {
	switch x := v.(type) {
	case nil, string, bool, float64:
		return v
	case map[string]any:
		var out map[string]any
		for k, item := range x {
			n := normalize(item)
			if out == nil && !sameValue(n, item) {
				out = make(map[string]any, len(x))
				for k2, item2 := range x {
					out[k2] = item2
				}
			}
			if out != nil {
				out[k] = n
			}
		}
		if out == nil {
			return x
		}
		return out
	case []any:
		var out []any
		for i, item := range x {
			n := normalize(item)
			if out == nil && !sameValue(n, item) {
				out = make([]any, len(x))
				copy(out, x)
			}
			if out != nil {
				out[i] = n
			}
		}
		if out == nil {
			return x
		}
		return out
	}
	if isScalarKind(v) {
		return normalizeScalar(v)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			break // []byte marshals as base64 text
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = normalize(rv.Index(i).Interface())
		}
		return out
	case reflect.Map:
		if rv.Type().Key().Kind() == reflect.String {
			if rv.IsNil() {
				return nil
			}
			out := make(map[string]any, rv.Len())
			iter := rv.MapRange()
			for iter.Next() {
				out[iter.Key().String()] = normalize(iter.Value().Interface())
			}
			return out
		}
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
	}
	// Structs and anything else: as encoding/json sees them.
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(data, &out) != nil {
		return v
	}
	return out
}

func isScalarKind(v any) bool {
	switch v.(type) {
	case float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return true
	}
	return false
}

// sameValue reports whether normalize left a value untouched (identity for
// maps and slices, equality for scalars).
func sameValue(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		return ok && reflect.ValueOf(x).UnsafePointer() == reflect.ValueOf(y).UnsafePointer()
	case []any:
		y, ok := b.([]any)
		return ok && len(x) == len(y) && (len(x) == 0 || &x[0] == &y[0])
	case float64:
		y, ok := b.(float64)
		return ok && (x == y || (math.IsNaN(x) && math.IsNaN(y)))
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	if a == nil || !reflect.TypeOf(a).Comparable() {
		return a == nil && b == nil
	}
	return a == b
}

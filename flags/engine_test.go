package flags

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type vectorFile struct {
	Murmur3 []struct {
		Input   string `json:"input"`
		Murmur3 uint32 `json:"murmur3"`
	} `json:"murmur3"`
	Text []struct {
		Value any     `json:"value"`
		Text  *string `json:"text"`
	} `json:"text"`
	Evaluations []struct {
		Name     string         `json:"name"`
		Flag     any            `json:"flag"`
		Context  map[string]any `json:"context"`
		Segments any            `json:"segments"`
		Expect   any            `json:"expect"`
	} `json:"evaluations"`
	Validation []struct {
		Name   string `json:"name"`
		Flag   any    `json:"flag"`
		Errors any    `json:"errors"`
	} `json:"validation"`
	SegmentValidation []struct {
		Name    string `json:"name"`
		Segment any    `json:"segment"`
		Errors  any    `json:"errors"`
	} `json:"segmentValidation"`
}

// loadVectors finds the shared vectors beside this SDK in the monorepo
// (sdk/flags-core) or inside the SDK's public mirror (flags-core/).
func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "flags-core", "testdata", "vectors.json"),
		filepath.Join("..", "flags-core", "testdata", "vectors.json"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var v vectorFile
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return v
	}
	t.Fatalf("vectors.json not found in %v", candidates)
	return vectorFile{}
}

// asJSON turns a result into decoded JSON, to compare with a vector's expectation.
func asJSON(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestVectorsMurmur3(t *testing.T) {
	v := loadVectors(t)
	if len(v.Murmur3) == 0 {
		t.Fatal("no murmur3 vectors")
	}
	for _, c := range v.Murmur3 {
		if got := Murmur3(c.Input); got != c.Murmur3 {
			t.Errorf("Murmur3(%q) = %d, want %d", c.Input, got, c.Murmur3)
		}
	}
}

func TestVectorsText(t *testing.T) {
	v := loadVectors(t)
	if len(v.Text) == 0 {
		t.Fatal("no text vectors")
	}
	for _, c := range v.Text {
		got, ok := TextOf(c.Value)
		switch {
		case c.Text == nil && ok:
			t.Errorf("TextOf(%v) = %q, want none", c.Value, got)
		case c.Text != nil && (!ok || got != *c.Text):
			t.Errorf("TextOf(%v) = %q (%v), want %q", c.Value, got, ok, *c.Text)
		}
	}
}

func TestVectorsEvaluations(t *testing.T) {
	v := loadVectors(t)
	if len(v.Evaluations) == 0 {
		t.Fatal("no evaluation vectors")
	}
	for _, c := range v.Evaluations {
		t.Run(c.Name, func(t *testing.T) {
			got := asJSON(t, Evaluate(c.Flag, c.Context, c.Segments))
			if !reflect.DeepEqual(got, c.Expect) {
				t.Errorf("got %v\nwant %v", got, c.Expect)
			}
		})
	}
}

func TestVectorsValidation(t *testing.T) {
	v := loadVectors(t)
	if len(v.Validation) == 0 {
		t.Fatal("no validation vectors")
	}
	for _, c := range v.Validation {
		t.Run(c.Name, func(t *testing.T) {
			got := asJSON(t, ValidateFlag(c.Flag))
			if !reflect.DeepEqual(got, c.Errors) {
				t.Errorf("got %v\nwant %v", got, c.Errors)
			}
		})
	}
}

func TestVectorsSegmentValidation(t *testing.T) {
	v := loadVectors(t)
	if len(v.SegmentValidation) == 0 {
		t.Fatal("no segment validation vectors")
	}
	for _, c := range v.SegmentValidation {
		t.Run(c.Name, func(t *testing.T) {
			got := asJSON(t, ValidateSegment(c.Segment))
			if !reflect.DeepEqual(got, c.Errors) {
				t.Errorf("got %v\nwant %v", got, c.Errors)
			}
		})
	}
}

func rolloutFlag(weights ...any) map[string]any {
	variations := []any{}
	ws := []any{}
	for i := 0; i < len(weights); i += 2 {
		key := weights[i].(string)
		variations = append(variations, map[string]any{"key": key, "value": key})
		ws = append(ws, map[string]any{"variation": key, "weight": weights[i+1]})
	}
	return map[string]any{
		"key": "dist", "type": "string", "variations": variations,
		"offVariation": weights[0], "on": true, "rules": []any{},
		"fallthrough": map[string]any{"rollout": map[string]any{"weights": ws}},
		"salt":        "salt",
	}
}

func TestRolloutDistributionFollowsWeights(t *testing.T) {
	flag := rolloutFlag("a", 10000, "b", 30000, "c", 60000)
	counts := map[string]int{}
	const n = 20000
	for i := 0; i < n; i++ {
		counts[Evaluate(flag, map[string]any{"key": fmt.Sprintf("user-%d", i)}, nil).Variation]++
	}
	for key, want := range map[string]float64{"a": 0.10, "b": 0.30, "c": 0.60} {
		if got := float64(counts[key]) / n; math.Abs(got-want) > 0.015 {
			t.Errorf("%s served %.3f of the time, want %.2f", key, got, want)
		}
	}
}

func TestBucketingIsStableAndNeverPanics(t *testing.T) {
	flag := rolloutFlag("a", 50000, "b", 50000)
	for i := 0; i < 200; i++ {
		ctx := map[string]any{"key": fmt.Sprintf("u%d", i)}
		if a, b := Evaluate(flag, ctx, nil), Evaluate(flag, ctx, nil); a.Variation != b.Variation || a.Reason.Bucket != b.Reason.Bucket {
			t.Fatalf("unstable bucketing for %v", ctx)
		}
	}
	if got := Evaluate(nil, nil, nil); got.Reason.Kind != ReasonError || got.Reason.ErrorKind != ErrorMalformedFlag || got.Variation != "" || got.Value != nil {
		t.Errorf("nil flag: %+v", got)
	}
	if got := Evaluate(flag, nil, "not a list"); got.Reason.Kind != ReasonFallthrough {
		t.Errorf("nil context: %+v", got)
	}
	for _, garbage := range []any{42, "x", []any{1}, map[string]any{"rules": "x"}, math.NaN(), make(chan int)} {
		if got := Evaluate(garbage, nil, garbage); got.Reason.Kind != ReasonError {
			t.Errorf("Evaluate(%v) = %+v", garbage, got)
		}
	}
}

func TestGoValuesAreTreatedAsJSON(t *testing.T) {
	flag := map[string]any{
		"key": "plan-gate", "type": "boolean",
		"variations":   []map[string]any{{"key": "on", "value": true}, {"key": "off", "value": false}},
		"offVariation": "off", "on": true,
		"rules": []map[string]any{{
			"id":         "adults",
			"conditions": []map[string]any{{"attribute": "age", "operator": "gte", "values": []int{18}}},
			"serve":      map[string]string{"variation": "on"},
		}},
		"fallthrough": map[string]any{"variation": "off"},
		"salt":        "s1",
	}
	if errs := ValidateFlag(flag); len(errs) != 0 {
		t.Fatalf("ValidateFlag: %v", errs)
	}
	if got := Evaluate(flag, map[string]any{"age": 21}, nil); got.Variation != "on" || got.Reason.Kind != ReasonRuleMatch {
		t.Errorf("age 21: %+v", got)
	}
	if got := Evaluate(flag, map[string]any{"age": int64(17)}, nil); got.Variation != "off" {
		t.Errorf("age 17: %+v", got)
	}
	if got := Evaluate(flag, map[string]any{"age": []uint8{20}}, nil); got.Variation != "off" {
		// []byte is text to encoding/json, not a list of numbers.
		t.Errorf("[]byte age: %+v", got)
	}
}

func TestNumberText(t *testing.T) {
	cases := map[float64]string{
		1e21: "1e+21", 1e20: "100000000000000000000", 1e-7: "1e-7", 1.5e-5: "0.000015",
		-0.0: "0", -1.5: "-1.5", 123e-20: "1.23e-18", 5e-324: "5e-324", math.MaxFloat64: "1.7976931348623157e+308",
		0.30000000000000004: "0.30000000000000004", 1234567: "1234567",
	}
	for in, want := range cases {
		if got, _ := TextOf(in); got != want {
			t.Errorf("TextOf(%v) = %q, want %q", in, got, want)
		}
	}
	if got, _ := TextOf(int64(-3)); got != "-3" {
		t.Errorf("TextOf(int64) = %q", got)
	}
	for in, want := range map[string]float64{"1.": 1, ".5": 0.5, "-.5": -0.5, "1e-400": 0, "007": 7, "1.e2": 100} {
		if got, ok := NumberOf(in); !ok || got != want {
			t.Errorf("NumberOf(%q) = %v, %v", in, got, ok)
		}
	}
	for _, in := range []string{"1e400", " 4", "0x10", "1_000", "", "-", "."} {
		if got, ok := NumberOf(in); ok {
			t.Errorf("NumberOf(%q) = %v, want none", in, got)
		}
	}
}

func TestLoneSurrogateHashesAsReplacementCharacter(t *testing.T) {
	// "\ud800" in JavaScript; Go strings carry it WTF-8 encoded.
	if Murmur3("a\xed\xa0\x80b") != Murmur3("a�b") {
		t.Error("a lone surrogate must hash as U+FFFD")
	}
}

func TestSegmentKeysOf(t *testing.T) {
	flag := map[string]any{"rules": []any{
		map[string]any{"conditions": []any{
			map[string]any{"attribute": "segment", "operator": "in_segment", "values": []any{"a", "b"}},
			map[string]any{"attribute": "plan", "operator": "in", "values": []any{"x"}},
		}},
		map[string]any{"conditions": []any{
			map[string]any{"attribute": "segment", "operator": "not_in_segment", "values": []any{"b", "c", 3}},
		}},
	}}
	if got := SegmentKeysOf(flag); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("SegmentKeysOf = %v", got)
	}
}

package rasp

import (
	"context"
	"encoding/xml"
	"testing"
)

func TestCodeHelpersContract(t *testing.T) {
	const input = "1); os.Exit(1"
	runSinkContract(t, sinkCase{
		name:   "rasp.CheckCode",
		attack: CodeInjection,
		inputs: AddInput(nil, input, "query.expr"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			if err := CheckCode(ctx, "expr.Compile", "print("+input+")"); err != nil {
				return false, err
			}
			return true, nil
		},
	})

	const doc = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://example.com/x.ent">]><r>hi</r>`
	runSinkContract(t, sinkCase{
		name:   "rasp.UnmarshalXML",
		attack: XXE,
		inputs: AddInput(nil, doc, "body"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			var v struct {
				XMLName xml.Name `xml:"r"`
				Text    string   `xml:",chardata"`
			}
			err := UnmarshalXML(ctx, []byte(doc), &v)
			return v.Text == "hi", err
		},
	})

	const yaml = "!!python/object/apply:os.system ['id']"
	runSinkContract(t, sinkCase{
		name:   "rasp.CheckDeserialization",
		attack: Deserialization,
		inputs: AddInput(nil, yaml, "body"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			if err := CheckDeserialization(ctx, "yaml.Unmarshal", DeserYAML, []byte(yaml)); err != nil {
				return false, err
			}
			return true, nil
		},
	})
}

func TestCodeHelperRules(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeBlock})
	ctx := requestCtx(AddInput(nil, "plain text", "query.q"), nil)
	if err := CheckCode(ctx, "", "a + b"); err != nil {
		t.Fatal(err)
	}
	if err := CheckXML(ctx, "", []byte("<r>plain text</r>"), true); err != nil {
		t.Fatal(err)
	}
	if err := CheckDeserialization(ctx, "", DeserYAML, []byte("a: plain text")); err != nil {
		t.Fatal(err)
	}
	// encoding/xml never resolves external entities: xxe.doctype, and
	// xxe.external_entity only for a parser that does.
	doc := []byte(`<!DOCTYPE r [<!ENTITY x SYSTEM "http://example.com/x.ent">]><r/>`)
	tctx := requestCtx(AddInput(nil, string(doc), "body"), nil)
	if b := AsBlocked(UnmarshalXML(tctx, doc, new(struct{}))); b == nil || b.Rule != "xxe.doctype" {
		t.Fatalf("got %v", b)
	}
	if b := AsBlocked(CheckXML(tctx, "libxml.parse", doc, true)); b == nil || b.Rule != "xxe.external_entity" {
		t.Fatalf("got %v", b)
	}
	ev := log.all()
	if len(ev) != 2 || ev[0].Attrs["shield360.rasp.sink"] != "xml.Unmarshal" || ev[1].Attrs["shield360.rasp.sink"] != "libxml.parse" {
		t.Fatalf("events %v", ev)
	}
	// Sink names outside the platform's shape fall back to the default.
	for in, want := range map[string]string{
		"expr.Compile": "expr.Compile", "a/b:c": "a/b:c", "": "d", "a..b": "d", "a.": "d",
		"1a": "d", "a b": "d", "a-b": "d", "a$b": "d",
	} {
		if got := sinkName(in, "d"); got != want {
			t.Errorf("sinkName(%q) = %q, want %q", in, got, want)
		}
	}
	if sinkWord("my-driver.v2", "x") != "my_driver_v2" || sinkWord("$$", "x") != "x" {
		t.Error("sinkWord")
	}
}

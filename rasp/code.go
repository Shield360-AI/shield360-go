package rasp

import (
	"context"
	"encoding/xml"
)

// Code, deserialization and XML sinks (README "Code", "Deserialization",
// "XXE"). Go has no eval and its standard library has no deserializer that
// runs code, so these are helpers for the call sites that do: an expression
// or script engine (expr, goja, otto, yaegi, a template compiled from
// text), a third-party decoder of one of the contract's formats, and XML.
// Each returns only the block error.

// CheckCode checks source text about to be evaluated (code.eval). sink
// names the call site in events (default "code.eval").
func CheckCode(ctx context.Context, sink, code string) error {
	if !Active() {
		return nil
	}
	inputs := inputsOf(ctx)
	if len(inputs) == 0 {
		return nil
	}
	return checkSink(ctx, sinkName(sink, "code.eval"), func(slot *iastSlot) *Finding { return detectCodeWith(code, inputs, slot) })
}

// CheckDeserialization checks data about to be decoded in one of the
// contract's formats (deser.*). sink names the call site (default
// "deserialize").
func CheckDeserialization(ctx context.Context, sink string, format DeserFormat, data []byte) error {
	if !Active() {
		return nil
	}
	inputs := inputsOf(ctx)
	if len(inputs) == 0 {
		return nil
	}
	return checkSink(ctx, sinkName(sink, "deserialize"), func(slot *iastSlot) *Finding {
		return detectDeserializationWith(format, string(data), inputs, slot)
	})
}

// CheckXML checks an XML document about to be parsed (xxe.*).
// resolvesExternal says whether the parser fetches external entities (a
// libxml2 binding configured to); Go's encoding/xml never does, and its
// findings are xxe.doctype. sink names the call site (default "xml.parse").
func CheckXML(ctx context.Context, sink string, data []byte, resolvesExternal bool) error {
	if !Active() {
		return nil
	}
	inputs := inputsOf(ctx)
	if len(inputs) == 0 {
		return nil
	}
	return checkSink(ctx, sinkName(sink, "xml.parse"), func(slot *iastSlot) *Finding {
		return detectXMLWith(string(data), inputs, resolvesExternal, slot)
	})
}

// UnmarshalXML is xml.Unmarshal with RASP checks. encoding/xml does not
// fetch external entities, so a tainted DOCTYPE that declares one is
// reported as xxe.doctype (monitor-level advice), and the protocol, file
// and entity-expansion rules apply as usual.
func UnmarshalXML(ctx context.Context, data []byte, v any) error {
	if err := CheckXML(ctx, "xml.Unmarshal", data, false); err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}

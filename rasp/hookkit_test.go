package rasp

import (
	"context"
	"sync/atomic"
	"testing"
)

// The Go version of the TypeScript hook kit (sdk/typescript/src/rasp/
// __tests__/hook-kit.ts): the checks every sink wrapper must pass, whoever
// wrote it. Each wrapper's own tests cover what its sink detects; the kit
// covers how it behaves around the call. Go has no install/uninstall (the
// wrappers are opt-in), so the kit's install, restore and shape checks
// become: block refuses before the underlying call, monitor reports exactly
// once and lets the call through, RASP off (and the runtime kill switch,
// and the attack type off) checks and reports nothing, a failing detector
// fails open, and the wrapper composes with another wrapper of the same
// kind in either order.

// sinkCall runs a sink once under ctx. ran reports whether the underlying
// operation happened.
type sinkCall func(t *testing.T, ctx context.Context) (ran bool, err error)

type sinkCase struct {
	name   string
	attack AttackType
	inputs []Input
	trees  []any
	allow  Allow
	// outside runs the call with no RASP context (outbound checks).
	outside bool
	// neverBlocks: block mode is monitor for this attack type (xss).
	neverBlocks bool
	call        sinkCall
	// composed are the same trigger through stacks with another wrapper.
	composed map[string]sinkCall
}

// requestCtx is ctx carrying a request's RASP context.
func requestCtx(inputs []Input, trees []any) context.Context {
	return withContext(context.Background(), &Context{
		inputs: inputs, trees: trees, inRequest: true,
		method: "GET", path: "/kit", framework: Framework,
	})
}

func eventsOf(log *eventLog, attack AttackType) []Event {
	var out []Event
	for _, e := range log.all() {
		if e.Attrs["shield360.rasp.attack"] == string(attack) {
			out = append(out, e)
		}
	}
	return out
}

// countChecks counts the sink checks that reach a detector.
func countChecks(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	f := func(string) { n.Add(1) }
	testHookDetect.Store(&f)
	t.Cleanup(func() { testHookDetect.Store(nil) })
	return &n
}

// failDetectors makes every sink detector panic.
func failDetectors(t *testing.T) {
	t.Helper()
	f := func(string) { panic("detector unavailable") }
	testHookDetect.Store(&f)
	t.Cleanup(func() { testHookDetect.Store(nil) })
}

func runSinkContract(t *testing.T, c sinkCase) {
	t.Helper()
	t.Run(c.name, func(t *testing.T) {
		ctxOf := func() context.Context {
			if c.outside {
				return context.Background()
			}
			return requestCtx(c.inputs, c.trees)
		}
		engine := func(t *testing.T, mode Mode, attacks map[AttackType]Mode) *eventLog {
			return setupEngine(t, engineSettings{mode: mode, attacks: attacks, allow: c.allow, modelOutput: true})
		}
		expectOne := func(t *testing.T, log *eventLog, decision Decision) {
			t.Helper()
			ev := eventsOf(log, c.attack)
			if len(ev) != 1 {
				t.Fatalf("want exactly one %s event, got %d (%v)", c.attack, len(ev), log.all())
			}
			if got := ev[0].Attrs["shield360.rasp.decision"]; got != string(decision) {
				t.Fatalf("decision %q, want %q", got, decision)
			}
		}
		expectBlocked := func(t *testing.T, call sinkCall, log *eventLog) {
			t.Helper()
			ran, err := call(t, ctxOf())
			if c.neverBlocks {
				if err != nil || !ran {
					t.Fatalf("never blocks: ran=%v err=%v", ran, err)
				}
				expectOne(t, log, DecisionMonitored)
				return
			}
			b := AsBlocked(err)
			if b == nil {
				t.Fatalf("want the block error, got ran=%v err=%v", ran, err)
			}
			if ran {
				t.Fatal("the underlying call ran although blocked")
			}
			if b.Attack != c.attack || b.EventID == "" {
				t.Fatalf("block error %+v", b)
			}
			expectOne(t, log, DecisionBlocked)
		}
		expectQuiet := func(t *testing.T, log *eventLog) {
			t.Helper()
			ran, err := c.call(t, ctxOf())
			if err != nil || !ran {
				t.Fatalf("want the call through, got ran=%v err=%v", ran, err)
			}
			if ev := eventsOf(log, c.attack); len(ev) != 0 {
				t.Fatalf("want no events, got %v", ev)
			}
		}

		t.Run("block refuses before the call and reports once", func(t *testing.T) {
			expectBlocked(t, c.call, engine(t, ModeBlock, nil))
		})
		t.Run("monitor lets the call through and reports exactly once", func(t *testing.T) {
			log := engine(t, ModeMonitor, nil)
			ran, err := c.call(t, ctxOf())
			if err != nil || !ran {
				t.Fatalf("ran=%v err=%v", ran, err)
			}
			expectOne(t, log, DecisionMonitored)
		})
		t.Run("RASP off checks and reports nothing", func(t *testing.T) {
			configureEngine(engineSettings{enabled: false, getenv: noEnv})
			log := &eventLog{}
			setEventSink(log)
			t.Cleanup(func() { setEventSink(nil) })
			n := countChecks(t)
			expectQuiet(t, log)
			if n.Load() != 0 {
				t.Fatalf("%d detector runs with RASP off", n.Load())
			}
		})
		t.Run("the kill switch checks and reports nothing", func(t *testing.T) {
			log := engine(t, ModeBlock, nil)
			Disable()
			t.Cleanup(Enable)
			n := countChecks(t)
			expectQuiet(t, log)
			if n.Load() != 0 {
				t.Fatalf("%d detector runs with the kill switch on", n.Load())
			}
		})
		t.Run("the attack type off reports nothing", func(t *testing.T) {
			expectQuiet(t, engine(t, ModeBlock, map[AttackType]Mode{c.attack: ModeOff}))
		})
		t.Run("a failing detector fails open", func(t *testing.T) {
			log := engine(t, ModeBlock, nil)
			failDetectors(t)
			ran, err := c.call(t, ctxOf())
			if err != nil || !ran {
				t.Fatalf("want fail-open, got ran=%v err=%v", ran, err)
			}
			if ev := log.all(); len(ev) != 0 {
				t.Fatalf("want no events, got %v", ev)
			}
		})
		for name, call := range c.composed {
			t.Run("composes: "+name, func(t *testing.T) {
				expectBlocked(t, call, engine(t, ModeBlock, nil))
			})
			t.Run("composes, monitor: "+name, func(t *testing.T) {
				log := engine(t, ModeMonitor, nil)
				ran, err := call(t, ctxOf())
				if err != nil || !ran {
					t.Fatalf("ran=%v err=%v", ran, err)
				}
				expectOne(t, log, DecisionMonitored)
			})
		}
	})
}

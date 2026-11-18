package rasp

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Several checks for one call: the finding with the strongest decision wins,
// so a finding in monitor or off mode never hides one that blocks.

func attacksOf(log *eventLog) [][2]string {
	var out [][2]string
	for _, e := range log.all() {
		out = append(out, [2]string{e.Attrs["shield360.rasp.attack"], e.Attrs["shield360.rasp.decision"]})
	}
	return out
}

func TestStrongestFinding(t *testing.T) {
	cmdi := &Finding{Attack: CommandInjection, Rule: "cmdi.userinput"}
	shell := &Finding{Attack: ShellSpawn, Rule: "shell_spawn.shell"}
	t.Run("block beats an earlier monitor", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock, attacks: map[AttackType]Mode{CommandInjection: ModeMonitor}})
		if got := Strongest(cmdi, shell); got != shell {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("an attack type that is off never counts", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeMonitor, attacks: map[AttackType]Mode{CommandInjection: ModeOff}})
		if got := Strongest(cmdi, shell); got != shell {
			t.Fatalf("got %v", got)
		}
		setupEngine(t, engineSettings{mode: ModeBlock, attacks: map[AttackType]Mode{CommandInjection: ModeOff, ShellSpawn: ModeOff}})
		if got := Strongest(cmdi, shell); got != nil {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("ties keep the contract's order", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		if got := Strongest(nil, cmdi, shell); got != cmdi {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("a rule's own action caps it", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		capped := &Finding{Attack: VirtualPatch, Rule: "vp", Action: ModeMonitor}
		if got := Strongest(capped, shell); got != shell {
			t.Fatalf("got %v", got)
		}
	})
}

func TestCommandInjectionOffDoesNotHideShellSpawnBlock(t *testing.T) {
	requireSh(t)
	const input = "kit; echo ok"
	for _, mode := range []Mode{ModeOff, ModeMonitor} {
		t.Run(string(mode), func(t *testing.T) {
			// Both fire: the input spans shell tokens (command_injection) and a
			// shell starts during a request (shell_spawn).
			log := setupEngine(t, engineSettings{mode: ModeBlock, attacks: map[AttackType]Mode{CommandInjection: mode, ShellSpawn: ModeBlock}})
			ctx := requestCtx(AddInput(nil, input, "query.name"), nil)
			err := CommandContext(ctx, "sh", "-c", "true "+input).Run()
			if b := AsBlocked(err); b == nil || b.Rule != "shell_spawn.shell" {
				t.Fatalf("argv: got %v", err)
			}
			if err := CheckShellCommand(ctx, "sh -c true "+input); AsBlocked(err) == nil || AsBlocked(err).Rule != "shell_spawn.shell" {
				t.Fatalf("shell line: got %v", err)
			}
			for _, a := range attacksOf(log) {
				if a != [2]string{"shell_spawn", "blocked"} {
					t.Fatalf("events %v", attacksOf(log))
				}
			}
		})
	}
}

func TestOutboundMonitorDoesNotHideSSRFBlock(t *testing.T) {
	srv, hits := hitServer(t)
	log := setupEngine(t, engineSettings{
		mode:    ModeBlock,
		attacks: map[AttackType]Mode{Outbound: ModeMonitor, SSRF: ModeBlock},
		allow:   Allow{OutboundHosts: []string{"api.example.com"}},
	})
	u := srv.URL + "/admin"
	ran, err := get(requestCtx(AddInput(nil, u, "query.url"), nil), NewTransport(nil), u, hits)
	if b := AsBlocked(err); b == nil || b.Rule != "ssrf.internal" || ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	if got := attacksOf(log); len(got) != 1 || got[0] != [2]string{"ssrf", "blocked"} {
		t.Fatalf("events %v", got)
	}
}

func TestRenameReportsTheStrongestOfItsPaths(t *testing.T) {
	dir := fileFixture(t)
	setupEngine(t, engineSettings{mode: ModeBlock, attacks: map[AttackType]Mode{PathTraversal: ModeMonitor, FileWrite: ModeBlock}})
	inputs := AddInput(AddInput(nil, traversal, "query.file"), "shell.php", "body.name")
	target := filepath.Join(dir, "shell.php")
	err := Rename(requestCtx(inputs, nil), dir+"/sub/"+traversal, target)
	if b := AsBlocked(err); b == nil || b.Rule != "file_write.script" {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("renamed")
	}
}

func TestOutboundMonitorDoesNotSkipTheResolvedSSRFCheck(t *testing.T) {
	srv, hits := hitServer(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	log := setupEngine(t, engineSettings{
		mode:    ModeBlock,
		attacks: map[AttackType]Mode{Outbound: ModeMonitor, SSRF: ModeBlock},
		allow:   Allow{OutboundHosts: []string{"api.example.com"}},
	})
	// An unlisted, tainted name that resolves to a loopback address: the
	// outbound finding (monitor) must not skip the address check (block).
	res := &fakeResolver{table: map[string][]string{"rebind.test": {"127.0.0.1"}}}
	u := "http://rebind.test:" + port + "/"
	ran, err := get(requestCtx(AddInput(nil, u, "query.url"), nil), raspTransportWith(res), u, hits)
	if b := AsBlocked(err); b == nil || b.Rule != "ssrf.internal" || ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	got := attacksOf(log)
	if len(got) != 2 || got[0] != [2]string{"outbound", "monitored"} || got[1] != [2]string{"ssrf", "blocked"} {
		t.Fatalf("events %v", got)
	}
}

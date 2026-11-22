package rasp

import (
	"context"
	"os/exec"
)

// os/exec sink (README "Command"). rasp.Command and rasp.CommandContext are
// drop-ins for exec.Command and exec.CommandContext: they build the same
// *exec.Cmd and check its argv when it is built. A blocked command gets the
// block error in cmd.Err, so Run, Start, Output and CombinedOutput return it
// without starting anything. Change cmd.Path or cmd.Args afterwards and the
// change is not checked.
//
// The argv is checked as the contract says for argv spawns: cmdi.executable
// (argv[0] is an input), the script of `sh -c <script>` (and bash, cmd /c,
// powershell -Command) through the shell-command rules, and shell_spawn for
// a shell or downloader started during a request unless allow.commands
// lists it. A downloader piped into a shell is reported at any time.

// Command is exec.Command with RASP checks. It has no request in scope, so
// only shell_spawn.download_exec applies; use CommandContext with the
// request's context.
func Command(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	guardCmd(context.Background(), cmd, "exec.Command")
	return cmd
}

// CommandContext is exec.CommandContext with RASP checks against the
// inputs in ctx.
func CommandContext(ctx context.Context, name string, arg ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, arg...)
	guardCmd(ctx, cmd, "exec.CommandContext")
	return cmd
}

func guardCmd(ctx context.Context, cmd *exec.Cmd, sink string) {
	if err := checkArgv(ctx, append([]string(nil), cmd.Args...), sink); err != nil {
		cmd.Err = err
	}
}

// CheckCommand checks an argv about to be started some other way
// (os.StartProcess, syscall.Exec, a process library). It returns only the
// block error.
func CheckCommand(ctx context.Context, argv []string) error {
	return checkArgv(ctx, append([]string(nil), argv...), "os.StartProcess")
}

// CheckShellCommand checks a command line a shell will interpret (handed to
// a remote shell, written to a script, passed to a library that runs it with
// sh -c). It returns only the block error.
func CheckShellCommand(ctx context.Context, command string) error {
	if !Active() {
		return nil
	}
	rc := FromContext(ctx)
	if err := checkSink(ctx, "shell.command", func(slot *iastSlot) *Finding {
		return detectShellLine(command, rc.Inputs(), rc.InRequest(), AllowLists().Commands, slot)
	}); err != nil {
		return err
	}
	return checkBackdoorShell(ctx, "shell.command", command)
}

func detectShellLine(command string, inputs []Input, inRequest bool, allow []string, slot *iastSlot) *Finding {
	return Strongest(shellLineFindings(command, inputs, inRequest, allow, slot)...)
}

// shellLineFindings is every finding of the contract's checks for a shell
// command line, in the contract's order.
func shellLineFindings(command string, inputs []Input, inRequest bool, allow []string, slot *iastSlot) []*Finding {
	return []*Finding{
		detectCommandWith(command, inputs, slot),
		DetectShellSpawn(Spawn{Command: command, InRequest: inRequest, Allow: allow}),
	}
}

// detectArgv runs the contract's argv checks in the TypeScript hook's
// order; the finding with the strongest decision wins, so one in monitor or
// off mode never hides one that blocks.
func detectArgv(argv []string, inputs []Input, inRequest bool, allow []string, slot *iastSlot) *Finding {
	if len(argv) == 0 {
		return nil
	}
	found := []*Finding{detectArgvWith(argv, inputs, slot)}
	if script, ok := ShellScriptOf(argv); ok && script != "" {
		// The script's own shell_spawn rule is download_exec only: the shell
		// itself is judged from argv[0] below.
		found = append(found, shellLineFindings(script, inputs, false, allow, slot)...)
	}
	found = append(found, DetectShellSpawn(Spawn{Argv0: argv[0], InRequest: inRequest, Allow: allow}))
	return Strongest(found...)
}

func checkArgv(ctx context.Context, argv []string, sink string) error {
	if !Active() || len(argv) == 0 {
		return nil
	}
	rc := FromContext(ctx)
	if err := checkSink(ctx, sink, func(slot *iastSlot) *Finding {
		return detectArgv(argv, rc.Inputs(), rc.InRequest(), AllowLists().Commands, slot)
	}); err != nil {
		return err
	}
	// Backdoor checks: a saved upload run as a program or by an interpreter.
	return checkBackdoorExec(ctx, sink, argv)
}

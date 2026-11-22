// Package rasp is Shield360 runtime application self-protection (RASP) for
// Go, opt-in. sdk/rasp/README.md in the Shield360 repository is the contract
// all Shield360 SDKs follow.
//
// The package tracks the untrusted input of the request being served (and the
// model output the SDK's LLM instrumentation has seen) in the request's
// context.Context and checks it where it reaches a dangerous sink. Fail open
// everywhere: the only error RASP returns on purpose is the block error
// (ErrBlocked), which Middleware turns into a 403.
//
// Turn it on with shield360.Init(shield360.Config{Rasp: &rasp.Options{}}) or
// SHIELD360_RASP=monitor|block, and wrap the HTTP handler:
//
//	http.ListenAndServe(":8080", rasp.Middleware(mux))
//
// Go has no runtime patching, so sinks are opt-in drop-ins that take the
// request's context: OpenSQL (database/sql), CheckMongo, CommandContext
// (os/exec), NewTransport and WrapClient (HTTP client), Open, ReadFile,
// WriteFile and the other file helpers, CheckCode, CheckDeserialization,
// UnmarshalXML, and CheckResponses (reflected XSS, monitor only).
//
// SHIELD360_RASP=off always wins.
package rasp

import (
	"errors"
	"fmt"
)

// AttackType names a class of attack (README "Attack types and modes").
type AttackType string

// The attack types of the contract.
const (
	SQLInjection     AttackType = "sql_injection"
	NoSQLInjection   AttackType = "nosql_injection"
	CommandInjection AttackType = "command_injection"
	ShellSpawn       AttackType = "shell_spawn"
	PathTraversal    AttackType = "path_traversal"
	FileWrite        AttackType = "file_write"
	SSRF             AttackType = "ssrf"
	Outbound         AttackType = "outbound"
	Deserialization  AttackType = "deserialization"
	CodeInjection    AttackType = "code_injection"
	XXE              AttackType = "xxe"
	XSS              AttackType = "xss"
	VirtualPatch     AttackType = "virtual_patch"
	Baseline         AttackType = "baseline"
	// CustomRuleAttack is the organization's own rules (README "Custom
	// rules"); a rule's action is capped by this mode.
	CustomRuleAttack AttackType = "custom_rule"
	// MaliciousUpload is what an uploaded file is (README "Uploads").
	MaliciousUpload AttackType = "malicious_upload"
	// UploadBackdoor is an uploaded file saved where it runs, loaded, run or
	// made executable (README "Uploads", "Backdoor checks").
	UploadBackdoor AttackType = "upload_backdoor"
)

// AttackTypes lists every attack type, in the contract's order.
var AttackTypes = []AttackType{
	SQLInjection, NoSQLInjection, CommandInjection, ShellSpawn, PathTraversal, FileWrite,
	SSRF, Outbound, Deserialization, CodeInjection, XXE, XSS, VirtualPatch, Baseline, CustomRuleAttack,
	MaliciousUpload, UploadBackdoor, AIAttackAgent,
}

// MonitorOnly reports whether an attack type only ever reports: block is
// treated as monitor (README "Attack types and modes").
func MonitorOnly(a AttackType) bool { return a == XSS || a == Baseline }

// Mode is what RASP does about an attack type.
type Mode string

// The modes of the contract.
const (
	ModeOff     Mode = "off"
	ModeMonitor Mode = "monitor"
	ModeBlock   Mode = "block"
)

// Source says where a piece of untrusted input came from.
type Source string

// The input sources of the contract.
const (
	SourceRequest     Source = "request"
	SourceModelOutput Source = "model_output"
)

// Input is one piece of untrusted input. Key is a location name
// (query.id, body.user.name); the value never leaves the process.
type Input struct {
	Value  string
	Key    string
	Source Source
}

// Finding is what a detector found.
type Finding struct {
	Attack AttackType
	Rule   string
	// Input is the input that caused the finding, when one did.
	Input *Input
	// CVE is set by virtual patches.
	CVE string
	// Action is the most the rule does (virtual patches, custom rules);
	// empty means no cap.
	Action Mode
	// Target is the raw destination an allow-list rule compared
	// (shell_spawn.shell, outbound.not_allowed, path.outside_root); the
	// event carries it masked, only with reportTargets (README "Allow-list
	// targets").
	Target string
	// Dialect is the dialect the SQL lexer used (sql_injection findings).
	Dialect SQLDialect
	// Mode, when set, decides instead of the attack type's mode (an upload
	// route's policy), capped like attack modes (README "Upload policy and
	// deep scan").
	Mode Mode
	// Upload is what the event says about an uploaded file (README "Upload
	// event attributes"); never a file name or content.
	Upload *UploadAttrs
}

// UploadAttrs are the upload event attributes (README "Upload event attributes").
type UploadAttrs struct {
	Type, Kind, Ext, SHA256, Signature, Engine, Dest, Action string
	Size                                                     int64
}

// Allow holds the contract's allow-lists.
type Allow struct {
	// Commands are executables (basename) allowed to run during requests
	// without a shell_spawn event.
	Commands []string
	// OutboundHosts is the outbound allow-list; empty means no outbound
	// check. "*.example.com" matches subdomains.
	OutboundHosts []string
	// FileRoots are the directories file access may use.
	FileRoots []string
}

// Decision is what happened to a finding.
type Decision string

// The decisions of the contract.
const (
	DecisionNone      Decision = ""
	DecisionBlocked   Decision = "blocked"
	DecisionMonitored Decision = "monitored"
)

// BlockMessage is the error text of the 403 body.
const BlockMessage = "Request blocked by Shield360 runtime protection"

// ErrBlocked is the block error of the contract. Every error a blocking
// check returns matches it with errors.Is; errors.As with *BlockedError
// gives the attack, the rule and the event id.
var ErrBlocked = errors.New("rasp: " + BlockMessage)

// BlockedError is returned by a blocking check. Middleware maps it to the
// contract's 403.
type BlockedError struct {
	Attack  AttackType
	Rule    string
	EventID string
	// RetryAfter is set on the deter answer (README "AI attack agents"): a
	// marked attack agent in block mode gets 429 with this Retry-After
	// (seconds) instead of the 403.
	RetryAfter int
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%s (%s, %s)", BlockMessage, e.Attack, e.Rule)
}

// Is makes errors.Is(err, ErrBlocked) true for every block error.
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

// StatusCode is the HTTP status the block error maps to: 403, or 429 for
// the deter answer.
func (e *BlockedError) StatusCode() int {
	if e.RetryAfter > 0 {
		return 429
	}
	return 403
}

// DeterMessage is the deter answer's error text.
const DeterMessage = "Too Many Requests"

// AsBlocked returns the block error in err's chain, or nil.
func AsBlocked(err error) *BlockedError {
	var b *BlockedError
	if errors.As(err, &b) {
		return b
	}
	return nil
}

// BlockBody is the JSON body of the 403 (README "The block response").
type BlockBody struct {
	Error  string     `json:"error"`
	Attack AttackType `json:"attack"`
	Rule   string     `json:"rule"`
	Event  string     `json:"event"`
}

// BodyOf builds the 403 body for a block error.
func BodyOf(e *BlockedError) BlockBody {
	return BlockBody{Error: BlockMessage, Attack: e.Attack, Rule: e.Rule, Event: e.EventID}
}

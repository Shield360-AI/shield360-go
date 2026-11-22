package rasp

import (
	"context"
	"io"
)

// Upload inspection for a gateway (README "Uploads", "Other layers"):
// Shield360 Edge inspects each multipart file part with the same scanner,
// signatures, policy and rule names as the SDKs, for one app behind it, and
// reports under its own sink.

// EdgeUploadSink is the sink of upload events Shield360 Edge raises.
const EdgeUploadSink = "edge.upload"

// UploadOptionsFor is the upload policy of a route (the event route of the
// request) from this app's verified signed config; the zero value when the
// config has no uploads block.
func (e *AppEngine) UploadOptionsFor(route string) UploadOptions {
	return uploadOptionsFrom(e.remote.Load(), route)
}

// uploadMode is the mode that decides an upload finding for this app: a
// route's own mode instead of the attack type's, capped by the kill switch,
// a local off and no pinned key, then by the finding's own cap.
func (e *AppEngine) uploadMode(f *Finding) Mode {
	m := e.ModeFor(f.Attack)
	if f.Mode != "" && e.Active() && e.local.attacks[f.Attack] != ModeOff {
		m = f.Mode
		if m == ModeBlock && (e.o.MonitorOnly || MonitorOnly(f.Attack)) {
			m = ModeMonitor
		}
	}
	if f.Action != "" && modeRank[f.Action] < modeRank[m] {
		m = f.Action
	}
	return m
}

// ReportUpload applies the policy o to a verdict and reports the file (one
// event, the strongest decision) under sink. It returns the decision and,
// when blocked, the block error. Nothing is reported when no finding
// decides more than off.
func (e *AppEngine) ReportUpload(ctx context.Context, v UploadVerdict, o UploadOptions, sink string, extra FindingExtra) (Decision, *BlockedError) {
	if !e.Active() {
		return DecisionNone, nil
	}
	best := strongestUpload(UploadFindings(v, o), e.uploadMode)
	if best == nil {
		return DecisionNone, nil
	}
	return e.Handle(ctx, nil, best, sink, extra)
}

// InspectUpload reads an uploaded file (bounded memory) and reports it for
// this app under EdgeUploadSink: the gateway's rasp.InspectUpload.
func (e *AppEngine) InspectUpload(ctx context.Context, r io.Reader, name, contentType string, o UploadOptions, extra FindingExtra) (UploadVerdict, Decision, *BlockedError) {
	s := o.NewScanner(name, contentType)
	if _, err := io.Copy(s, r); err != nil {
		return s.Finish(false), DecisionNone, nil
	}
	v := s.Finish(true)
	d, b := e.ReportUpload(ctx, v, o, EdgeUploadSink, extra)
	return v, d, b
}

// UploadEventAttrs are README "Upload event attributes" for a verdict and
// one of its findings, each only when it has its shape (for a gateway that
// reports a file without an engine). Never a file name or content.
func UploadEventAttrs(v UploadVerdict, f UploadFinding) map[string]string {
	attrs := map[string]string{}
	addUploadAttrs(attrs, &Finding{Attack: MaliciousUpload, Upload: &UploadAttrs{Type: v.Type, Kind: v.Kind, Ext: v.Ext, Size: v.Size, SHA256: v.SHA256, Signature: f.Signature, Engine: f.Engine}})
	return attrs
}

// UploadBlocks reports whether the built-in upload findings on a route with
// policy o block for this app (so a gateway must not forward an upload it
// could not inspect).
func (e *AppEngine) UploadBlocks(o UploadOptions) bool {
	return e.uploadMode(&Finding{Attack: MaliciousUpload, Mode: o.Mode}) == ModeBlock
}

package shield360

// Version is the current version of the Shield360 Go SDK.
//
// This is the single source of truth. Releases go through the Release /
// Packages workflow, which tags this repository `sdk-go-<Version>`; the mirror
// sync then tags Shield360-AI/shield360-go `v<Version>`, which is the tag Go
// itself resolves, because a module's import path is its repository URL and
// this repository is private.
const Version = "1.1.1"

// Package core holds device-independent logic: inventory loaded from the
// user's config.yaml, desired vs. observed state and the drift between them,
// the apply engine, and the scheduler.
//
// It depends on the driver interface, never on a concrete device. See
// DESIGN.md, "Architecture".
package core

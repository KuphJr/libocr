package ocr3types

import (
	"context"
	"time"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type MercuryPluginFactory interface {
	// Creates a new reporting plugin instance. The instance may have
	// associated goroutines or hold system resources, which should be
	// released when its Close() function is called.
	NewMercuryPlugin(MercuryPluginConfig) (MercuryPlugin, MercuryPluginInfo, error)
}

type MercuryPluginConfig struct {
	ConfigDigest types.ConfigDigest

	// OracleID (index) of the oracle executing this ReportingPlugin instance.
	OracleID commontypes.OracleID

	// N is the total number of nodes.
	N int

	// F is an upper bound on the number of faulty nodes.
	F int

	// Encoded configuration for the contract
	OnchainConfig []byte

	// Encoded configuration for the ReportingPlugin disseminated through the
	// contract. This value is only passed through the contract, but otherwise
	// ignored by it.
	OffchainConfig []byte

	// Estimate of the duration between rounds. You should not rely on this
	// value being accurate. Rounds might occur more or less frequently than
	// estimated.
	//
	// This value is intended for estimating the load incurred by a
	// ReportingPlugin before running it and for configuring caches.
	EstimatedRoundInterval time.Duration

	// Maximum duration the ReportingPlugin's functions are allowed to take
	MaxDurationObservation time.Duration
}

// A MercuryPlugin allows plugging custom logic into the OCR protocol. The OCR
// protocol handles cryptography, networking, ensuring that a sufficient number
// of nodes is in agreement about any report, transmitting the report to the
// contract, etc... The MercuryPlugin handles application-specific logic. To do
// so, the MercuryPlugin defines a number of callbacks that are called by the
// OCR protocol logic at certain points in the protocol's execution flow. The
// report generated by the MercuryPlugin must be in a format understood by
// contract that the reports are transmitted to.
//
// We assume that each correct node participating in the protocol instance will
// be running the same MercuryPlugin implementation. However, not all nodes may
// be correct; up to f nodes be faulty in arbitrary ways (aka byzantine faults).
// For example, faulty nodes could be down, have intermittent connectivity
// issues, send garbage messages, or be controlled by an adversary.
//
// For a protocol round where everything is working correctly, followers will
// call Observation and Report. If a sufficient number of followers agree on a
// report, ShouldAcceptFinalizedReport will be called as well. If
// ShouldAcceptFinalizedReport returns true, ShouldTransmitAcceptedReport will
// be called. However, a MercuryPlugin must also correctly handle the case where
// faults occur.
//
// In particular, a MercuryPlugin must deal with cases where:
//
// - only a subset of the functions on the MercuryPlugin are invoked for a given
// round
//
// - an arbitrary number of epochs and rounds has been skipped between
// invocations of the MercuryPlugin
//
// - the observation returned by Observation is not included in the list of
// AttributedObservations passed to Report
//
// - an observation is malformed. (For defense in depth, it is also strongly
// recommended that malformed reports are handled gracefully.)
//
// - instances of the MercuryPlugin run by different oracles have different call
// traces. E.g., the MercuryPlugin's Observation function may have been invoked
// on node A, but not on node B.
//
// All functions on a MercuryPlugin should be thread-safe.
//
// All functions that take a context as their first argument may still do cheap
// computations after the context expires, but should stop any blocking
// interactions with outside services (APIs, database, ...) and return as
// quickly as possible. (Rough rule of thumb: any such computation should not
// take longer than a few ms.) A blocking function may block execution of the
// entire protocol instance!
//
// For a given OCR protocol instance, there can be many (consecutive) instances
// of a MercuryPlugin, e.g. due to software restarts. If you need MercuryPlugin
// state to survive across restarts, you should persist it. A MercuryPlugin
// instance will only ever serve a single protocol instance. When we talk about
// "instance" below, we typically mean MercuryPlugin instances, not protocol
// instances.
type MercuryPlugin interface {
	// Observation gets an observation from the underlying data source. Returns
	// a value or an error.
	//
	// You may assume that previousReport contains the last report that was
	// generated by the protocol instance, even if the MercuryPlugin instance
	// or the process hosting it were restarted in the meantime. The "genesis"
	// previousReport is empty.
	//
	// You may assume that the sequence of epochs and the sequence of rounds
	// within an epoch are strictly monotonically increasing during the lifetime
	// of an instance of this interface.
	Observation(ctx context.Context, repts types.ReportTimestamp, previousReport types.Report) (types.Observation, error)

	// Decides whether a report (destined for the contract) should be generated
	// in this round. If yes, also constructs the report.
	//
	// You may assume that previousReport contains the last report that was
	// generated by the protocol instance, even if the MercuryPlugin instance
	// or the process hosting it were restarted in the meantime. The "genesis"
	// previousReport is empty.
	//
	// You may assume that the sequence of epochs and the sequence of rounds
	// within an epoch are strictly monotonically increasing during the lifetime
	// of an instance of this interface.
	Report(repts types.ReportTimestamp, previousReport types.Report, aos []types.AttributedObservation) (bool, types.Report, error)

	// If Close is called a second time, it may return an error but must not
	// panic. This will always be called when a ReportingPlugin is no longer
	// needed, e.g. on shutdown of the protocol instance or shutdown of the
	// oracle node. This will only be called after any calls to other functions
	// of the ReportingPlugin will have completed.
	Close() error
}

const (
	twoMiB                         = 2 * 1024 * 1024 // 2 MiB
	MaxMaxMercuryObservationLength = twoMiB          // 2 MiB
	MaxMaxMercuryReportLength      = twoMiB          // 2 MiB
)

type MercuryPluginLimits struct {
	// Maximum length in bytes of Observation, Report returned by the
	// MercuryPlugin. Used for defending against spam attacks.
	MaxObservationLength int
	MaxReportLength      int
}

type MercuryPluginInfo struct {
	// Used for debugging purposes.
	Name string

	Limits MercuryPluginLimits
}

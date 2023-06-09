package protocol

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/internal/loghelper"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/internal/config/ocr3config"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/internal/ocr3/protocol/pool"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/libocr/subprocesses"
)

const futureMessageBufferSize = 10 // big enough for a couple of full rounds of outgen protocol

func RunOutcomeGeneration[RI any](
	ctx context.Context,
	subprocesses *subprocesses.Subprocesses,

	chNetToOutcomeGeneration <-chan MessageToOutcomeGenerationWithSender[RI],
	chPacemakerToOutcomeGeneration <-chan EventToOutcomeGeneration[RI],
	chOutcomeGenerationToPacemaker chan<- EventToPacemaker[RI],
	chOutcomeGenerationToReportAttestation chan<- EventToReportAttestation[RI],
	config ocr3config.SharedConfig,
	database Database,
	id commontypes.OracleID,
	localConfig types.LocalConfig,
	logger loghelper.LoggerWithContext,
	netSender NetworkSender[RI],
	offchainKeyring types.OffchainKeyring,
	reportingPlugin ocr3types.OCR3Plugin[RI],
	telemetrySender TelemetrySender,

	restoredCert CertifiedPrepareOrCommit,
) {
	outgen := outcomeGenerationState[RI]{
		ctx:          ctx,
		subprocesses: subprocesses,

		chNetToOutcomeGeneration:               chNetToOutcomeGeneration,
		chPacemakerToOutcomeGeneration:         chPacemakerToOutcomeGeneration,
		chOutcomeGenerationToPacemaker:         chOutcomeGenerationToPacemaker,
		chOutcomeGenerationToReportAttestation: chOutcomeGenerationToReportAttestation,
		config:                                 config,
		database:                               database,
		id:                                     id,
		localConfig:                            localConfig,
		logger:                                 logger.MakeUpdated(commontypes.LogFields{"proto": "outgen"}),
		netSender:                              netSender,
		offchainKeyring:                        offchainKeyring,
		reportingPlugin:                        reportingPlugin,
		telemetrySender:                        telemetrySender,
	}
	outgen.run(restoredCert)
}

type outcomeGenerationState[RI any] struct {
	ctx          context.Context
	subprocesses *subprocesses.Subprocesses

	chNetToOutcomeGeneration               <-chan MessageToOutcomeGenerationWithSender[RI]
	chPacemakerToOutcomeGeneration         <-chan EventToOutcomeGeneration[RI]
	chOutcomeGenerationToPacemaker         chan<- EventToPacemaker[RI]
	chOutcomeGenerationToReportAttestation chan<- EventToReportAttestation[RI]
	config                                 ocr3config.SharedConfig
	database                               Database
	e                                      uint64 // Current epoch number
	id                                     commontypes.OracleID
	l                                      commontypes.OracleID // Current leader number
	localConfig                            types.LocalConfig
	logger                                 loghelper.LoggerWithContext
	netSender                              NetworkSender[RI]
	offchainKeyring                        types.OffchainKeyring
	reportingPlugin                        ocr3types.OCR3Plugin[RI]
	telemetrySender                        TelemetrySender

	bufferedMessages []*MessageBuffer[RI]
	leaderState      leaderState
	followerState    followerState[RI]
}

type leaderState struct {
	phase outgenLeaderPhase

	startRoundQuorumCertificate StartEpochProof

	readyToStartRound bool
	tRound            <-chan time.Time

	query        types.Query
	observations map[commontypes.OracleID]*SignedObservation
	tGrace       <-chan time.Time
}

type followerState[RI any] struct {
	phase outgenFollowerPhase

	firstSeqNrOfEpoch uint64

	seqNr uint64

	roundStartPool *pool.Pool[MessageRoundStart[RI]]

	query *types.Query

	proposalPool *pool.Pool[MessageProposal[RI]]

	currentOutcomeInputsDigest OutcomeInputsDigest
	currentOutcome             ocr3types.Outcome
	currentOutcomeDigest       OutcomeDigest

	// lock
	cert CertifiedPrepareOrCommit

	preparePool *pool.Pool[PrepareSignature]
	commitPool  *pool.Pool[CommitSignature]

	deliveredSeqNr   uint64
	deliveredOutcome ocr3types.Outcome
}

// Run starts the event loop for the report-generation protocol
func (outgen *outcomeGenerationState[RI]) run(restoredCert CertifiedPrepareOrCommit) {
	outgen.logger.Info("Running OutcomeGeneration", nil)

	for i := 0; i < outgen.config.N(); i++ {
		outgen.bufferedMessages = append(outgen.bufferedMessages, NewMessageBuffer[RI](futureMessageBufferSize))
	}

	// Initialization
	outgen.leaderState = leaderState{
		outgenLeaderPhaseUnknown,
		StartEpochProof{
			nil,
			nil,
		},
		false,
		nil,
		nil,
		nil,
		nil,
	}

	outgen.followerState = followerState[RI]{
		outgenFollowerPhaseUnknown,
		0,
		0,
		nil,
		nil,
		nil,
		OutcomeInputsDigest{},
		nil,
		OutcomeDigest{},
		restoredCert,
		nil,
		nil,

		0,
		nil,
	}

	// AXE
	// if outgen.id == outgen.l {
	// 	outgen.startRound()
	// 	outgen.startRound()
	// }

	// Event Loop
	chDone := outgen.ctx.Done()
	for {
		select {
		case msg := <-outgen.chNetToOutcomeGeneration:
			msg.msg.processOutcomeGeneration(outgen, msg.sender)
		case ev := <-outgen.chPacemakerToOutcomeGeneration:
			ev.processOutcomeGeneration(outgen)
		case <-outgen.leaderState.tGrace:
			outgen.eventTGraceTimeout()
		case <-outgen.leaderState.tRound:
			outgen.eventTRoundTimeout()
		case <-chDone:
		}

		// ensure prompt exit
		select {
		case <-chDone:
			outgen.logger.Info("OutcomeGeneration: exiting", commontypes.LogFields{
				"e": outgen.e,
				"l": outgen.l,
			})
			return
		default:
		}
	}
}

func (outgen *outcomeGenerationState[RI]) messageToOutcomeGeneration(msg MessageToOutcomeGeneration[RI], sender commontypes.OracleID) {
	msgEpoch := msg.epoch()
	if msgEpoch < outgen.e {
		// drop
		outgen.logger.Debug("dropping message for past epoch", commontypes.LogFields{
			"epoch":    outgen.e,
			"msgEpoch": msgEpoch,
			"sender":   sender,
		})
	} else if msgEpoch == outgen.e {
		msg.processOutcomeGeneration(outgen, sender)
	} else {
		outgen.bufferedMessages[sender].Push(msg)
		outgen.logger.Trace("buffering message for future epoch", commontypes.LogFields{
			"epoch":    outgen.e,
			"msgEpoch": msgEpoch,
			"sender":   sender,
		})
	}
}

func (outgen *outcomeGenerationState[RI]) unbufferMessages() {
	outgen.logger.Trace("getting messages for new epoch", commontypes.LogFields{
		"epoch": outgen.e,
	})
	for i, buffer := range outgen.bufferedMessages {
		sender := commontypes.OracleID(i)
		for {
			msg := buffer.Peek()
			if msg == nil {
				// no messages left in buffer
				break
			}
			msgEpoch := (*msg).epoch()
			if msgEpoch < outgen.e {
				buffer.Pop()
				outgen.logger.Debug("unbuffered and dropped message", commontypes.LogFields{
					"epoch":    outgen.e,
					"msgEpoch": msgEpoch,
					"sender":   sender,
				})
			} else if msgEpoch == outgen.e {
				buffer.Pop()
				outgen.logger.Trace("unbuffered messages for new epoch", commontypes.LogFields{
					"epoch":    outgen.e,
					"msgEpoch": msgEpoch,
					"sender":   sender,
				})
				(*msg).processOutcomeGeneration(outgen, sender)
			} else { // msgEpoch > e
				// this and all subsequent messages are for future epochs
				// leave them in the buffer
				break
			}
		}
	}
	outgen.logger.Trace("done unbuffering messages for new epoch", commontypes.LogFields{
		"epoch": outgen.e,
	})
}

func (outgen *outcomeGenerationState[RI]) eventStartNewEpoch(ev EventNewEpochStart[RI]) {
	// Initialization
	outgen.logger.Info("Starting new epoch", commontypes.LogFields{
		"epoch": ev.Epoch,
	})

	outgen.e = ev.Epoch
	outgen.l = Leader(outgen.e, outgen.config.N(), outgen.config.LeaderSelectionKey())

	outgen.logger = outgen.logger.MakeUpdated(commontypes.LogFields{
		"e": outgen.e,
		"l": outgen.l,
	})

	outgen.followerState.phase = outgenFollowerPhaseNewEpoch
	outgen.followerState.firstSeqNrOfEpoch = 0
	outgen.followerState.seqNr = 0
	outgen.followerState.currentOutcomeInputsDigest = OutcomeInputsDigest{}
	outgen.followerState.currentOutcome = nil
	outgen.followerState.currentOutcomeDigest = OutcomeDigest{}

	outgen.followerState.roundStartPool = pool.NewPool[MessageRoundStart[RI]](10)
	outgen.followerState.proposalPool = pool.NewPool[MessageProposal[RI]](10)
	outgen.followerState.preparePool = pool.NewPool[PrepareSignature](10)
	outgen.followerState.commitPool = pool.NewPool[CommitSignature](10)

	outgen.leaderState.phase = outgenLeaderPhaseNewEpoch

	outgen.leaderState.startRoundQuorumCertificate = StartEpochProof{
		nil,
		nil,
	}
	outgen.leaderState.readyToStartRound = false
	outgen.leaderState.tGrace = nil

	var highestCertified CertifiedPrepareOrCommit
	var highestCertifiedTimestamp HighestCertifiedTimestamp
	highestCertified = outgen.followerState.cert
	highestCertifiedTimestamp = outgen.followerState.cert.Timestamp()

	signedHighestCertifiedTimestamp, err := MakeSignedHighestCertifiedTimestamp(
		outgen.Timestamp(),
		highestCertifiedTimestamp,
		outgen.offchainKeyring.OffchainSign,
	)
	if err != nil {
		outgen.logger.Error("error signing timestamp", commontypes.LogFields{
			"error": err,
		})
		return
	}

	outgen.logger.Info("Sending MessageEpochStartRequest to leader", commontypes.LogFields{
		"epoch":                     ev.Epoch,
		"leader":                    outgen.l,
		"highestCertifiedTimestamp": highestCertifiedTimestamp,
	})
	outgen.netSender.SendTo(MessageEpochStartRequest[RI]{
		outgen.e,
		highestCertified,
		signedHighestCertifiedTimestamp,
	}, outgen.l)

	if outgen.id == outgen.l {
		outgen.leaderState.tRound = time.After(outgen.config.DeltaRound)
	}

	outgen.unbufferMessages()
}

func (outgen *outcomeGenerationState[RI]) Timestamp() Timestamp {
	return Timestamp{outgen.config.ConfigDigest, outgen.e}
}

func (outgen *outcomeGenerationState[RI]) OutcomeCtx(seqNr uint64) ocr3types.OutcomeContext {
	if seqNr != outgen.followerState.deliveredSeqNr+1 {
		outgen.logger.Critical("Assumption violation, seqNr isn't successor to deliveredSeqNr", commontypes.LogFields{
			"seqNr":          seqNr,
			"deliveredSeqNr": outgen.followerState.deliveredSeqNr,
		})
		panic("")
	}
	return ocr3types.OutcomeContext{
		seqNr,
		outgen.followerState.deliveredOutcome,
		uint64(outgen.e),
		seqNr - outgen.followerState.firstSeqNrOfEpoch + 1,
	}
}

func callPlugin[T any, RI any](
	outgen *outcomeGenerationState[RI],
	name string,
	maxDuration time.Duration,
	outctx ocr3types.OutcomeContext,
	f func(context.Context, ocr3types.OutcomeContext) (T, error),
) (T, bool) {
	ctx, cancel := context.WithTimeout(outgen.ctx, maxDuration)
	defer cancel()

	outgen.logger.Debug(fmt.Sprintf("calling ReportingPlugin.%s", name), commontypes.LogFields{
		"seqNr":       outctx.SeqNr,
		"round":       outctx.Round, // nolint: staticcheck
		"maxDuration": maxDuration,
	})

	// copy to avoid races when used inside the following closure
	logger := outgen.logger

	ins := loghelper.NewIfNotStopped(
		maxDuration+ReportingPluginTimeoutWarningGracePeriod,
		func() {
			logger.Error(fmt.Sprintf("call to ReportingPlugin.%s is taking too long", name), commontypes.LogFields{
				"seqNr":       outctx.SeqNr,
				"maxDuration": maxDuration,
			})
		},
	)

	result, err := f(ctx, outctx)

	ins.Stop()

	if err != nil {
		outgen.logger.ErrorIfNotCanceled(fmt.Sprintf("call to ReportingPlugin.%s errored", name), outgen.ctx, commontypes.LogFields{
			"seqNr": outctx.SeqNr,
			"error": err,
		})
		// failed to get data, nothing to be done
		var zero T
		return zero, false
	}

	return result, true
}

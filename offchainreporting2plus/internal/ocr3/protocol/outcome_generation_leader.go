package protocol

import (
	"context"
	"time"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type outgenLeaderPhase string

const (
	outgenLeaderPhaseUnknown        outgenLeaderPhase = "unknown"
	outgenLeaderPhaseNewEpoch       outgenLeaderPhase = "newEpoch"
	outgenLeaderPhaseSentStartEpoch outgenLeaderPhase = "sentStartEpoch"
	outgenLeaderPhaseSentStartRound outgenLeaderPhase = "sentStartRound"
	outgenLeaderPhaseGrace          outgenLeaderPhase = "grace"
	outgenLeaderPhaseSentPropose    outgenLeaderPhase = "sentPropose"
)

func (outgen *outcomeGenerationState[RI]) messageEpochStartRequest(msg MessageEpochStartRequest[RI], sender commontypes.OracleID) {
	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessageEpochStartRequest for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if outgen.l != outgen.id {
		outgen.logger.Warn("Non-leader received MessageEpochStartRequest", commontypes.LogFields{
			"sender": sender,
		})
		return
	}

	if outgen.leaderState.phase != outgenLeaderPhaseNewEpoch {
		outgen.logger.Debug("Got MessageEpochStartRequest for wrong phase", commontypes.LogFields{
			"sender": sender,
			"phase":  outgen.leaderState.phase,
		})
		return
	}

	{
		err := msg.HighestCertified.Verify(
			outgen.config.ConfigDigest,
			outgen.config.OracleIdentities,
			outgen.config.ByzQuorumSize(),
		)
		if err != nil {
			outgen.logger.Warn("MessageEpochStartRequest.HighestCertified is invalid", commontypes.LogFields{
				"sender": sender,
				"error":  err,
			})
			return
		}
	}

	{
		err := msg.SignedHighestCertifiedTimestamp.Verify(
			outgen.Timestamp(),
			outgen.config.OracleIdentities[sender].OffchainPublicKey,
		)
		if err != nil {
			outgen.logger.Warn("MessageEpochStartRequest.SignedHighestCertifiedTimestamp is invalid", commontypes.LogFields{
				"sender": sender,
				"error":  err,
			})
			return
		}
	}

	if msg.HighestCertified.Timestamp() != msg.SignedHighestCertifiedTimestamp.HighestCertifiedTimestamp {
		outgen.logger.Warn("Timestamp mismatch in MessageEpochStartRequest", commontypes.LogFields{
			"sender": sender,
		})
		return
	}

	for _, ashct := range outgen.leaderState.startRoundQuorumCertificate.HighestCertifiedProof {
		if ashct.Signer == sender {
			outgen.logger.Warn("MessageEpochStartRequest.HighestCertified is duplicate", commontypes.LogFields{
				"sender": sender,
			})
			return
		}
	}

	outgen.logger.Debug("Received valid MessageEpochStartRequest", commontypes.LogFields{
		"sender":                    sender,
		"highestCertifiedTimestamp": msg.SignedHighestCertifiedTimestamp.HighestCertifiedTimestamp,
	})

	outgen.leaderState.startRoundQuorumCertificate.HighestCertifiedProof = append(outgen.leaderState.startRoundQuorumCertificate.HighestCertifiedProof, AttributedSignedHighestCertifiedTimestamp{
		msg.SignedHighestCertifiedTimestamp,
		sender,
	})

	if outgen.leaderState.startRoundQuorumCertificate.HighestCertified == nil || outgen.leaderState.startRoundQuorumCertificate.HighestCertified.Timestamp().Less(msg.HighestCertified.Timestamp()) {
		outgen.leaderState.startRoundQuorumCertificate.HighestCertified = msg.HighestCertified
	}

	if len(outgen.leaderState.startRoundQuorumCertificate.HighestCertifiedProof) == outgen.config.ByzQuorumSize() {
		if err := outgen.leaderState.startRoundQuorumCertificate.Verify(outgen.Timestamp(), outgen.config.OracleIdentities, outgen.config.ByzQuorumSize()); err != nil {
			outgen.logger.Critical("StartRoundQuorumCertificate is invalid, very surprising!", commontypes.LogFields{
				"qc": outgen.leaderState.startRoundQuorumCertificate,
			})
			return
		}

		outgen.leaderState.phase = outgenLeaderPhaseSentStartEpoch

		outgen.logger.Info("Broadcasting MessageEpochStart", nil)

		outgen.netSender.Broadcast(MessageEpochStart[RI]{
			outgen.e,
			outgen.leaderState.startRoundQuorumCertificate,
		})

		if outgen.leaderState.startRoundQuorumCertificate.HighestCertified.IsGenesis() {
			outgen.followerState.firstSeqNrOfEpoch = outgen.followerState.deliveredSeqNr + 1
			outgen.startSubsequentLeaderRound()
		} else if commitQC, ok := outgen.leaderState.startRoundQuorumCertificate.HighestCertified.(*CertifiedPrepareOrCommitCommit); ok {
			outgen.deliver(*commitQC)
			outgen.followerState.firstSeqNrOfEpoch = outgen.followerState.deliveredSeqNr + 1
			outgen.startSubsequentLeaderRound()
		} else {
			prepareQc := outgen.leaderState.startRoundQuorumCertificate.HighestCertified.(*CertifiedPrepareOrCommitPrepare)
			outgen.followerState.firstSeqNrOfEpoch = prepareQc.SeqNr + 1
			// We're dealing with a re-proposal from a failed epoch based on a
			// prepare qc.
			// We don't want to send OBSERVER-REQ.
		}
	}
}

func (outgen *outcomeGenerationState[RI]) eventTRoundTimeout() {
	outgen.logger.Debug("TRound fired", commontypes.LogFields{
		"deltaRoundMilliseconds": outgen.config.DeltaRound.Milliseconds(),
	})
	outgen.startSubsequentLeaderRound()
}

func (outgen *outcomeGenerationState[RI]) startSubsequentLeaderRound() {
	if !outgen.leaderState.readyToStartRound {
		outgen.leaderState.readyToStartRound = true
		return
	}

	query, ok := callPlugin[types.Query](
		outgen,
		"Query",
		outgen.config.MaxDurationQuery,
		outgen.OutcomeCtx(outgen.followerState.deliveredSeqNr+1),
		func(ctx context.Context, outctx ocr3types.OutcomeContext) (types.Query, error) {
			return outgen.reportingPlugin.Query(ctx, outctx)
		},
	)
	if !ok {
		return
	}

	outgen.leaderState.query = query

	outgen.leaderState.observations = map[commontypes.OracleID]*SignedObservation{}

	outgen.leaderState.tRound = time.After(outgen.config.DeltaRound)
	outgen.leaderState.readyToStartRound = false

	outgen.leaderState.phase = outgenLeaderPhaseSentStartRound
	outgen.logger.Debug("Broadcasting MessageRoundStart", commontypes.LogFields{
		"seqNr": outgen.followerState.deliveredSeqNr + 1,
	})
	outgen.netSender.Broadcast(MessageRoundStart[RI]{
		outgen.e,
		outgen.followerState.deliveredSeqNr + 1,
		query, // query
	})
}

func (outgen *outcomeGenerationState[RI]) messageObservation(msg MessageObservation[RI], sender commontypes.OracleID) {

	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessageObservation for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if outgen.l != outgen.id {
		outgen.logger.Warn("Non-leader received MessageObservation", commontypes.LogFields{
			"sender": sender,
		})
		return
	}

	if outgen.leaderState.phase != outgenLeaderPhaseSentStartRound && outgen.leaderState.phase != outgenLeaderPhaseGrace {
		outgen.logger.Debug("Got MessageObservation for wrong phase", commontypes.LogFields{
			"sender": sender,
			"phase":  outgen.leaderState.phase,
		})
		return
	}

	if msg.SeqNr != outgen.followerState.seqNr {
		outgen.logger.Debug("Got MessageObservation with invalid SeqNr", commontypes.LogFields{
			"sender":   sender,
			"msgSeqNr": msg.SeqNr,
			"seqNr":    outgen.followerState.seqNr,
		})
		return
	}

	if outgen.leaderState.observations[sender] != nil {
		outgen.logger.Warn("Got duplicate MessageObservation", commontypes.LogFields{
			"sender": sender,
			"seqNr":  outgen.followerState.seqNr,
		})
		return
	}

	if err := msg.SignedObservation.Verify(outgen.Timestamp(), outgen.leaderState.query, outgen.config.OracleIdentities[sender].OffchainPublicKey); err != nil {
		outgen.logger.Warn("MessageObservation carries invalid SignedObservation", commontypes.LogFields{
			"sender": sender,
			"error":  err,
		})
		return
	}

	outgen.logger.Debug("Got valid MessageObservation", commontypes.LogFields{
		"seqNr": outgen.followerState.seqNr,
	})

	outgen.leaderState.observations[sender] = &msg.SignedObservation

	observationCount := 0
	for _, so := range outgen.leaderState.observations {
		if so != nil {
			observationCount++
		}
	}
	if observationCount == 2*outgen.config.F+1 {
		outgen.logger.Debug("starting observation grace period", commontypes.LogFields{})
		outgen.leaderState.phase = outgenLeaderPhaseGrace
		outgen.leaderState.tGrace = time.After(outgen.config.DeltaGrace)
	}
}

func (outgen *outcomeGenerationState[RI]) eventTGraceTimeout() {
	if outgen.leaderState.phase != outgenLeaderPhaseGrace {
		outgen.logger.Error("leader's phase conflicts tGrace timeout", commontypes.LogFields{
			"phase": outgen.leaderState.phase,
		})
		return
	}
	asos := []AttributedSignedObservation{}
	for oid, so := range outgen.leaderState.observations {
		if so != nil {
			asos = append(asos, AttributedSignedObservation{
				*so,
				commontypes.OracleID(oid),
			})
		}
	}

	outgen.leaderState.phase = outgenLeaderPhaseSentPropose

	outgen.logger.Debug("Broadcasting MessageProposal", commontypes.LogFields{})
	outgen.netSender.Broadcast(MessageProposal[RI]{
		outgen.e,
		outgen.followerState.seqNr,
		asos,
	})
}

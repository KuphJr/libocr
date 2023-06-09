package protocol

import (
	"context"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/internal/ocr3/protocol/pool"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type outgenFollowerPhase string

const (
	outgenFollowerPhaseUnknown     outgenFollowerPhase = "unknown"
	outgenFollowerPhaseNewEpoch    outgenFollowerPhase = "newEpoch"
	outgenFollowerPhaseReady       outgenFollowerPhase = "ready"
	outgenFollowerPhaseSentObserve outgenFollowerPhase = "sentObserve"
	outgenFollowerPhaseSentPrepare outgenFollowerPhase = "sentPrepare"
	outgenFollowerPhaseSentCommit  outgenFollowerPhase = "sentCommit"
)

///////////////////////////////////////////////////////////
// Outcome generation Follower
///////////////////////////////////////////////////////////

func (outgen *outcomeGenerationState[RI]) messageEpochStart(msg MessageEpochStart[RI], sender commontypes.OracleID) {
	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessageEpochStart for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if sender != outgen.l {
		outgen.logger.Warn("Non-leader sent MessageEpochStart", commontypes.LogFields{
			"sender": sender,
		})
		return
	}

	if outgen.followerState.phase != outgenFollowerPhaseNewEpoch {
		outgen.logger.Warn("Got MessageEpochStart for wrong phase", commontypes.LogFields{
			"sender": sender,
			"phase":  outgen.followerState.phase,
		})
		return
	}

	{
		err := msg.StartEpochProof.Verify(
			outgen.Timestamp(),
			outgen.config.OracleIdentities,
			outgen.config.ByzQuorumSize(),
		)
		if err != nil {
			outgen.logger.Warn("MessageEpochStart contains invalid StartRoundQuorumCertificate", commontypes.LogFields{
				"sender": outgen.l,
				"error":  err,
			})
			return
		}
	}

	if msg.StartEpochProof.HighestCertified.IsGenesis() {
		outgen.followerState.firstSeqNrOfEpoch = outgen.followerState.deliveredSeqNr + 1
		outgen.startSubsequentFollowerRound()
	} else if commitQC, ok := msg.StartEpochProof.HighestCertified.(*CertifiedPrepareOrCommitCommit); ok {
		outgen.deliver(*commitQC)
		outgen.followerState.firstSeqNrOfEpoch = outgen.followerState.deliveredSeqNr + 1
		outgen.startSubsequentFollowerRound()
	} else {
		// We're dealing with a re-proposal from a failed epoch

		prepareQc := msg.StartEpochProof.HighestCertified.(*CertifiedPrepareOrCommitPrepare)

		outcomeDigest := MakeOutcomeDigest(prepareQc.Outcome)

		prepareSignature, err := MakePrepareSignature(
			outgen.Timestamp(),
			prepareQc.SeqNr,
			OutcomeInputsDigest{},
			outcomeDigest,
			outgen.offchainKeyring.OffchainSign,
		)
		if err != nil {
			outgen.logger.Critical("Failed to sign Prepare", commontypes.LogFields{
				"error": err,
			})
			return
		}

		outgen.followerState.phase = outgenFollowerPhaseSentPrepare
		outgen.followerState.firstSeqNrOfEpoch = prepareQc.SeqNr + 1
		outgen.followerState.seqNr = prepareQc.SeqNr
		outgen.followerState.currentOutcome = prepareQc.Outcome
		outgen.followerState.currentOutcomeDigest = outcomeDigest
		outgen.logger.Debug("Broadcasting MessagePrepare (reproposal)", commontypes.LogFields{
			"seqNr": prepareQc.SeqNr,
		})
		outgen.netSender.Broadcast(MessagePrepare[RI]{
			outgen.e,
			prepareQc.SeqNr,
			prepareSignature,
		})
	}
}

func (outgen *outcomeGenerationState[RI]) startSubsequentFollowerRound() {
	outgen.followerState.phase = outgenFollowerPhaseReady
	outgen.followerState.seqNr = outgen.followerState.deliveredSeqNr + 1
	outgen.followerState.query = nil
	outgen.followerState.currentOutcome = nil
	outgen.followerState.currentOutcomeDigest = OutcomeDigest{}

	outgen.tryProcessRoundStartPool()
}

func (outgen *outcomeGenerationState[RI]) messageRoundStart(msg MessageRoundStart[RI], sender commontypes.OracleID) {
	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessageRoundStart for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if sender != outgen.l {
		outgen.logger.Warn("Non-leader sent MessageRoundStart", commontypes.LogFields{
			"sender": sender,
		})
		return
	}

	if putResult := outgen.followerState.roundStartPool.Put(msg.SeqNr, sender, msg); putResult != pool.PutResultOK {
		outgen.logger.Warn("Dropping MessageRoundStart", commontypes.LogFields{
			"sender": sender,
			"seqNr":  msg.SeqNr,
			"reason": putResult,
		})
		return
	}

	outgen.logger.Debug("Pooled MessageRoundStart", commontypes.LogFields{
		"sender": sender,
		"seqNr":  msg.SeqNr,
	})

	outgen.tryProcessRoundStartPool()
}

func (outgen *outcomeGenerationState[RI]) tryProcessRoundStartPool() {
	if outgen.followerState.phase != outgenFollowerPhaseReady {
		outgen.logger.Debug("cannot process RoundStartPool, wrong phase", commontypes.LogFields{
			"phase": outgen.followerState.phase,
		})
		return
	}

	poolEntries := outgen.followerState.roundStartPool.Entries(outgen.followerState.seqNr)

	if poolEntries == nil || poolEntries[outgen.l] == nil {

		outgen.logger.Debug("cannot process RoundStartPool, it's empty", commontypes.LogFields{
			"followerStateSeqNr": outgen.followerState.seqNr,
		})
		return
	}

	if outgen.followerState.query != nil {
		outgen.logger.Warn("cannot process RoundStartPool, query already set", commontypes.LogFields{
			"seqNr": outgen.followerState.seqNr,
		})
		return
	}

	msg := poolEntries[outgen.l].Item

	outgen.followerState.query = &msg.Query

	o, ok := callPlugin[types.Observation](
		outgen,
		"Observation",
		outgen.config.MaxDurationObservation,
		outgen.OutcomeCtx(outgen.followerState.seqNr),
		func(ctx context.Context, outctx ocr3types.OutcomeContext) (types.Observation, error) {
			return outgen.reportingPlugin.Observation(ctx, outctx, *outgen.followerState.query)
		},
	)
	if !ok {
		return
	}

	so, err := MakeSignedObservation(outgen.Timestamp(), msg.Query, o, outgen.offchainKeyring.OffchainSign)
	if err != nil {
		outgen.logger.Error("messageRoundStart: could not make SignedObservation observation", commontypes.LogFields{
			"seqNr": outgen.followerState.seqNr,
			"error": err,
		})
		return
	}

	if err := so.Verify(outgen.Timestamp(), msg.Query, outgen.offchainKeyring.OffchainPublicKey()); err != nil {
		outgen.logger.Error("MakeSignedObservation produced invalid signature:", commontypes.LogFields{
			"seqNr": outgen.followerState.seqNr,
			"error": err,
		})
		return
	}

	outgen.followerState.phase = outgenFollowerPhaseSentObserve
	outgen.logger.Debug("sent observation to leader", commontypes.LogFields{
		"seqNr": outgen.followerState.seqNr,
	})
	outgen.netSender.SendTo(MessageObservation[RI]{
		outgen.e,
		outgen.followerState.seqNr,
		so,
	}, outgen.l)

	outgen.tryProcessProposalPool()
}

func (outgen *outcomeGenerationState[RI]) messageProposal(msg MessageProposal[RI], sender commontypes.OracleID) {
	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessageProposal for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if sender != outgen.l {
		outgen.logger.Warn("Non-leader sent MessageProposal", commontypes.LogFields{
			"msgSeqNr": msg.SeqNr,
			"sender":   sender,
		})
		return
	}

	if putResult := outgen.followerState.proposalPool.Put(msg.SeqNr, sender, msg); putResult != pool.PutResultOK {
		outgen.logger.Warn("Dropping MessageProposal", commontypes.LogFields{
			"sender": sender,
			"seqNr":  msg.SeqNr,
			"reason": putResult,
		})
		return
	}

	outgen.logger.Debug("Pooled MessageProposal", commontypes.LogFields{
		"sender": sender,
		"seqNr":  msg.SeqNr,
	})

	outgen.tryProcessProposalPool()
}

func (outgen *outcomeGenerationState[RI]) tryProcessProposalPool() {
	if outgen.followerState.phase != outgenFollowerPhaseSentObserve {
		outgen.logger.Debug("cannot process ProposalPool, wrong phase", commontypes.LogFields{
			"phase": outgen.followerState.phase,
		})
		return
	}

	poolEntries := outgen.followerState.proposalPool.Entries(outgen.followerState.seqNr)

	if poolEntries == nil || poolEntries[outgen.l] == nil {

		return
	}

	msg := poolEntries[outgen.l].Item

	if msg.SeqNr <= outgen.followerState.deliveredSeqNr {
		outgen.logger.Critical("MessageProposal contains invalid SeqNr", commontypes.LogFields{
			"sender":         outgen.l,
			"msgSeqNr":       msg.SeqNr,
			"deliveredSeqNr": outgen.followerState.deliveredSeqNr,
		})
		return
	}

	attributedObservations := []types.AttributedObservation{}
	{
		if len(msg.AttributedSignedObservations) <= 2*outgen.config.F {
			outgen.logger.Debug("MessageProposal contains too few signed observations", nil)
			return
		}
		seen := map[commontypes.OracleID]bool{}
		for _, aso := range msg.AttributedSignedObservations {
			if !(0 <= int(aso.Observer) && int(aso.Observer) <= outgen.config.N()) {
				outgen.logger.Debug("MessageProposal contains signed observation with invalid observer", commontypes.LogFields{
					"invalidObserver": aso.Observer,
				})
				return
			}

			if seen[aso.Observer] {
				outgen.logger.Debug("MessageProposal contains duplicate signed observation", nil)
				return
			}

			seen[aso.Observer] = true

			if err := aso.SignedObservation.Verify(outgen.Timestamp(), *outgen.followerState.query, outgen.config.OracleIdentities[aso.Observer].OffchainPublicKey); err != nil {
				outgen.logger.Debug("MessageProposal contains signed observation with invalid signature", nil)
				return
			}

			attributedObservations = append(attributedObservations, types.AttributedObservation{
				aso.SignedObservation.Observation,
				aso.Observer,
			})
		}
	}

	outcomeInputsDigest := MakeOutcomeInputsDigest(
		outgen.Timestamp(),
		outgen.followerState.deliveredOutcome,
		outgen.followerState.seqNr,
		*outgen.followerState.query,
		attributedObservations,
	)

	outcome, ok := callPlugin[ocr3types.Outcome](
		outgen,
		"Outcome",
		0,
		outgen.OutcomeCtx(outgen.followerState.seqNr),
		func(_ context.Context, outctx ocr3types.OutcomeContext) (ocr3types.Outcome, error) {
			return outgen.reportingPlugin.Outcome(outctx, *outgen.followerState.query, attributedObservations)
		},
	)
	if !ok {
		return
	}

	outcomeDigest := MakeOutcomeDigest(outcome)

	prepareSignature, err := MakePrepareSignature(
		outgen.Timestamp(),
		msg.SeqNr,
		outcomeInputsDigest,
		outcomeDigest,
		outgen.offchainKeyring.OffchainSign,
	)
	if err != nil {
		outgen.logger.Critical("Failed to sign Prepare", commontypes.LogFields{
			"error": err,
		})
		return
	}

	outgen.followerState.phase = outgenFollowerPhaseSentPrepare
	outgen.followerState.currentOutcomeInputsDigest = outcomeInputsDigest
	outgen.followerState.currentOutcome = outcome
	outgen.followerState.currentOutcomeDigest = outcomeDigest

	outgen.logger.Debug("Broadcasting MessagePrepare", commontypes.LogFields{
		"seqNr": msg.SeqNr,
	})
	outgen.netSender.Broadcast(MessagePrepare[RI]{
		outgen.e,
		msg.SeqNr,
		prepareSignature,
	})
}

func (outgen *outcomeGenerationState[RI]) messagePrepare(msg MessagePrepare[RI], sender commontypes.OracleID) {
	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessagePrepare for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if putResult := outgen.followerState.preparePool.Put(msg.SeqNr, sender, msg.Signature); putResult != pool.PutResultOK {
		outgen.logger.Debug("Dropping MessagePrepare", commontypes.LogFields{
			"sender": sender,
			"seqNr":  msg.SeqNr,
			"reason": putResult,
		})
		return
	}

	outgen.logger.Debug("Pooled MessagePrepare", commontypes.LogFields{
		"sender": sender,
		"seqNr":  msg.SeqNr,
	})

	outgen.tryProcessPreparePool()
}

func (outgen *outcomeGenerationState[RI]) tryProcessPreparePool() {
	if outgen.followerState.phase != outgenFollowerPhaseSentPrepare {
		outgen.logger.Debug("cannot process PreparePool, wrong phase", commontypes.LogFields{
			"phase": outgen.followerState.phase,
		})
		return
	}

	poolEntries := outgen.followerState.preparePool.Entries(outgen.followerState.seqNr)
	if len(poolEntries) < outgen.config.ByzQuorumSize() {

		return
	}

	for sender, preparePoolEntry := range poolEntries {
		if preparePoolEntry == nil {
			continue
		}
		if preparePoolEntry.Verified != nil {
			continue
		}
		err := preparePoolEntry.Item.Verify(
			outgen.Timestamp(),
			outgen.followerState.seqNr,
			outgen.followerState.currentOutcomeInputsDigest,
			outgen.followerState.currentOutcomeDigest,
			outgen.config.OracleIdentities[sender].OffchainPublicKey,
		)
		ok := err == nil
		outgen.followerState.preparePool.StoreVerified(outgen.followerState.seqNr, sender, ok)
		if !ok {
			outgen.logger.Warn("Got invalid MessagePrepare", commontypes.LogFields{
				"sender": sender,
				"seqNr":  outgen.followerState.seqNr,
				"error":  err,
			})
		}
	}

	var prepareQuorumCertificate []AttributedPrepareSignature
	for sender, preparePoolEntry := range poolEntries {
		if preparePoolEntry.Verified != nil && *preparePoolEntry.Verified {
			prepareQuorumCertificate = append(prepareQuorumCertificate, AttributedPrepareSignature{
				preparePoolEntry.Item,
				sender,
			})
			if len(prepareQuorumCertificate) == outgen.config.ByzQuorumSize() {
				break
			}
		}
	}

	if len(prepareQuorumCertificate) < outgen.config.ByzQuorumSize() {
		return
	}

	commitSignature, err := MakeCommitSignature(
		outgen.Timestamp(),
		outgen.followerState.seqNr,
		outgen.followerState.currentOutcomeDigest,
		outgen.offchainKeyring.OffchainSign,
	)
	if err != nil {
		outgen.logger.Critical("Failed to sign Commit", commontypes.LogFields{
			"error": err,
		})
		return
	}

	outgen.followerState.cert = &CertifiedPrepareOrCommitPrepare{
		outgen.e,
		outgen.followerState.seqNr,
		outgen.followerState.currentOutcomeInputsDigest,
		outgen.followerState.currentOutcome,
		prepareQuorumCertificate,
	}
	if !outgen.persistCert() {
		return
	}

	outgen.followerState.phase = outgenFollowerPhaseSentCommit

	outgen.logger.Debug("Broadcasting MessageCommit", commontypes.LogFields{})
	outgen.netSender.Broadcast(MessageCommit[RI]{
		outgen.e,
		outgen.followerState.seqNr,
		commitSignature,
	})
}

func (outgen *outcomeGenerationState[RI]) messageCommit(msg MessageCommit[RI], sender commontypes.OracleID) {
	if msg.Epoch != outgen.e {
		outgen.logger.Debug("Got MessageCommit for wrong epoch", commontypes.LogFields{
			"sender":   sender,
			"msgEpoch": msg.Epoch,
		})
		return
	}

	if putResult := outgen.followerState.commitPool.Put(msg.SeqNr, sender, msg.Signature); putResult != pool.PutResultOK {
		outgen.logger.Debug("Dropping MessageCommit", commontypes.LogFields{
			"sender": sender,
			"seqNr":  msg.SeqNr,
			"reason": putResult,
		})
		return
	}

	outgen.logger.Debug("Pooled MessageCommit", commontypes.LogFields{
		"sender": sender,
		"seqNr":  msg.SeqNr,
	})

	outgen.tryProcessCommitPool()
}

func (outgen *outcomeGenerationState[RI]) tryProcessCommitPool() {
	if outgen.followerState.phase != outgenFollowerPhaseSentCommit {
		outgen.logger.Debug("cannot process CommitPool, wrong phase", commontypes.LogFields{
			"phase": outgen.followerState.phase,
		})
		return
	}

	poolEntries := outgen.followerState.commitPool.Entries(outgen.followerState.seqNr)
	if len(poolEntries) < outgen.config.ByzQuorumSize() {

		return
	}

	for sender, commitPoolEntry := range poolEntries {
		if commitPoolEntry == nil {
			continue
		}
		if commitPoolEntry.Verified != nil {
			continue
		}
		err := commitPoolEntry.Item.Verify(
			outgen.Timestamp(),
			outgen.followerState.seqNr,
			outgen.followerState.currentOutcomeDigest,
			outgen.config.OracleIdentities[sender].OffchainPublicKey,
		)
		ok := err == nil
		commitPoolEntry.Verified = &ok
		if !ok {
			outgen.logger.Warn("Got invalid MessageCommit", commontypes.LogFields{
				"sender": sender,
			})
		}
	}

	var commitQuorumCertificate []AttributedCommitSignature
	for sender, commitPoolEntry := range poolEntries {
		if commitPoolEntry.Verified != nil && *commitPoolEntry.Verified {
			commitQuorumCertificate = append(commitQuorumCertificate, AttributedCommitSignature{
				commitPoolEntry.Item,
				sender,
			})
			if len(commitQuorumCertificate) == outgen.config.ByzQuorumSize() {
				break
			}
		}
	}

	if len(commitQuorumCertificate) < outgen.config.ByzQuorumSize() {
		return
	}

	outgen.deliver(CertifiedPrepareOrCommitCommit{
		outgen.e,
		outgen.followerState.seqNr,
		outgen.followerState.currentOutcome,
		commitQuorumCertificate,
	})

	if uint64(outgen.config.RMax) <= outgen.followerState.seqNr-outgen.followerState.firstSeqNrOfEpoch+1 {
		outgen.logger.Debug("epoch has been going on for too long, sending EventChangeLeader to Pacemaker", commontypes.LogFields{
			"seqNr": outgen.followerState.seqNr,
		})
		select {
		case outgen.chOutcomeGenerationToPacemaker <- EventNewEpochRequest[RI]{}:
		case <-outgen.ctx.Done():
			return
		}
		return
	} else {
		outgen.logger.Debug("sending EventProgress to Pacemaker", commontypes.LogFields{
			"seqNr": outgen.followerState.seqNr,
		})
		select {
		case outgen.chOutcomeGenerationToPacemaker <- EventProgress[RI]{}:
		case <-outgen.ctx.Done():
			return
		}
	}

	outgen.startSubsequentFollowerRound()
	if outgen.id == outgen.l {
		outgen.startSubsequentLeaderRound()
	}

	outgen.tryProcessRoundStartPool()
}

func (outgen *outcomeGenerationState[RI]) deliver(commit CertifiedPrepareOrCommitCommit) {
	if commit.SeqNr < outgen.followerState.deliveredSeqNr {
		outgen.logger.Critical("Assumption violation, commitSeqNr is less than deliveredSeqNr", commontypes.LogFields{
			"commitSeqNr":    commit.SeqNr,
			"deliveredSeqNr": outgen.followerState.deliveredSeqNr,
		})
		return
	}

	if commit.SeqNr <= outgen.followerState.deliveredSeqNr {

		outgen.logger.Debug("Skipping delivery of already delivered outcome", commontypes.LogFields{
			"seqNr":          commit.SeqNr,
			"deliveredSeqNr": outgen.followerState.deliveredSeqNr,
		})
	} else {
		outgen.followerState.cert = &commit
		if !outgen.persistCert() {
			return
		}

		outgen.followerState.deliveredSeqNr = commit.SeqNr
		outgen.followerState.deliveredOutcome = commit.Outcome

		outgen.logger.Debug("✅ Delivered outcome", commontypes.LogFields{
			"seqNr": commit.SeqNr,
		})

		select {
		case outgen.chOutcomeGenerationToReportAttestation <- EventCommittedOutcome[RI]{commit}:
		case <-outgen.ctx.Done():
			return
		}
	}

	outgen.followerState.roundStartPool.ReapDelivered(outgen.followerState.deliveredSeqNr)
	outgen.followerState.proposalPool.ReapDelivered(outgen.followerState.deliveredSeqNr)
	outgen.followerState.preparePool.ReapDelivered(outgen.followerState.deliveredSeqNr)
	outgen.followerState.commitPool.ReapDelivered(outgen.followerState.deliveredSeqNr)
}

func (outgen *outcomeGenerationState[RI]) persistCert() (ok bool) {
	ctx, cancel := context.WithTimeout(outgen.ctx, outgen.localConfig.DatabaseTimeout)
	defer cancel()
	if err := outgen.database.WriteCert(ctx, outgen.config.ConfigDigest, outgen.followerState.cert); err != nil {
		outgen.logger.Error("Error persisting cert to database. Cannot safely continue current round.", commontypes.LogFields{
			"error": err,
		})
		return false
	}
	return true
}

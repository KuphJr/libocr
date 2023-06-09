package protocol

import (
	"context"
	"math"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/internal/loghelper"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/internal/config/ocr3config"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/internal/ocr3/scheduler"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

func RunReportAttestation[RI any](
	ctx context.Context,

	chNetToReportAttestation <-chan MessageToReportAttestationWithSender[RI],
	chReportAttestationToTransmission chan<- EventToTransmission[RI],
	chOutcomeGenerationToReportAttestation <-chan EventToReportAttestation[RI],
	config ocr3config.SharedConfig,
	contractSigner ocr3types.OnchainKeyring[RI],
	contractTransmitter ocr3types.ContractTransmitter[RI],
	logger loghelper.LoggerWithContext,
	netSender NetworkSender[RI],
	reportingPlugin ocr3types.OCR3Plugin[RI],
) {
	newReportAttestationState(ctx, chNetToReportAttestation,
		chReportAttestationToTransmission, chOutcomeGenerationToReportAttestation,
		config, contractSigner, contractTransmitter, logger, netSender, reportingPlugin).run()
}

const minExpirationAgeRounds int = 10
const expirationAgeDuration = 10 * time.Minute
const maxExpirationAgeRounds int = 1_000

const deltaRequestCertifiedCommit = 200 * time.Millisecond

type reportAttestationState[RI any] struct {
	ctx context.Context

	chNetToReportAttestation               <-chan MessageToReportAttestationWithSender[RI]
	chReportAttestationToTransmission      chan<- EventToTransmission[RI]
	chOutcomeGenerationToReportAttestation <-chan EventToReportAttestation[RI]
	config                                 ocr3config.SharedConfig
	contractSigner                         ocr3types.OnchainKeyring[RI]
	contractTransmitter                    ocr3types.ContractTransmitter[RI]
	logger                                 loghelper.LoggerWithContext
	netSender                              NetworkSender[RI]
	reportingPlugin                        ocr3types.OCR3Plugin[RI]

	scheduler *scheduler.Scheduler[EventMissingOutcome[RI]]
	// reap() is used to prevent unbounded state growth of finalized
	finalized             map[uint64]*finalizationRound[RI]
	finalizedHighestSeqNr uint64
}

type finalizationRound[RI any] struct {
	certifiedCommit *CertifiedPrepareOrCommitCommit
	reportsWithInfo []ocr3types.ReportWithInfo[RI]
	signatures      map[commontypes.OracleID]*reportSignatures
	startedFetch    bool
	complete        bool
}

type reportSignatures struct {
	signatures       [][]byte
	validSignatures  *bool
	requestedOutcome bool
	suppliedOutcome  bool
}

// func (fr finalizationRound) finalized(f int) bool {
// 	return len(fr.reportSignatures) > f
// }

func (repatt *reportAttestationState[RI]) run() {
	for {
		select {
		case msg := <-repatt.chNetToReportAttestation:
			msg.msg.processReportAttestation(repatt, msg.sender)
		case ev := <-repatt.chOutcomeGenerationToReportAttestation:
			ev.processReportAttestation(repatt)
		case ev := <-repatt.scheduler.Scheduled():
			ev.processReportAttestation(repatt)
		case <-repatt.ctx.Done():
		}

		// ensure prompt exit
		select {
		case <-repatt.ctx.Done():
			repatt.logger.Info("ReportAttestation: exiting", nil)
			repatt.scheduler.Close()
			return
		default:
		}
	}
}

func (repatt *reportAttestationState[RI]) messageReportSignatures(
	msg MessageReportSignatures[RI],
	sender commontypes.OracleID,
) {

	if repatt.isExpired(msg.SeqNr) {
		repatt.logger.Debug("ignoring MessageReportSignatures for expired SeqNr", commontypes.LogFields{
			"seqNr":  msg.SeqNr,
			"sender": sender,
		})
		return
	}

	if _, ok := repatt.finalized[msg.SeqNr]; !ok {
		repatt.finalized[msg.SeqNr] = &finalizationRound[RI]{
			nil,
			nil,
			map[commontypes.OracleID]*reportSignatures{},
			false,
			false,
		}
	}

	if _, ok := repatt.finalized[msg.SeqNr].signatures[sender]; ok {
		repatt.logger.Debug("ignoring MessageReportSignatures with duplicate signature", commontypes.LogFields{
			"seqNr":  msg.SeqNr,
			"sender": sender,
		})
		return
	}

	repatt.finalized[msg.SeqNr].signatures[sender] = &reportSignatures{
		msg.ReportSignatures,
		nil,
		false,
		false,
	}

	repatt.tryComplete(msg.SeqNr)
}

func (repatt *reportAttestationState[RI]) eventMissingOutcome(ev EventMissingOutcome[RI]) {
	if len(repatt.finalized[ev.SeqNr].reportsWithInfo) != 0 {
		repatt.logger.Debug("dropping EventMissingOutcome, already have Outcome", commontypes.LogFields{
			"seqNr": ev.SeqNr,
		})
		return
	}

	repatt.tryRequestCertifiedCommit(ev.SeqNr)
}

func (repatt *reportAttestationState[RI]) messageCertifiedCommitRequest(msg MessageCertifiedCommitRequest[RI], sender commontypes.OracleID) {
	if repatt.finalized[msg.SeqNr] == nil || repatt.finalized[msg.SeqNr].certifiedCommit == nil {
		repatt.logger.Warn("dropping MessageCertifiedCommitRequest for outcome with unknown certified commit", commontypes.LogFields{
			"seqNr":  msg.SeqNr,
			"sender": sender,
		})
		return
	}

	repatt.logger.Debug("sending MessageCertifiedCommit", commontypes.LogFields{
		"seqNr": msg.SeqNr,
		"to":    sender,
	})
	repatt.netSender.SendTo(MessageCertifiedCommit[RI]{*repatt.finalized[msg.SeqNr].certifiedCommit}, sender)

}

func (repatt *reportAttestationState[RI]) messageCertifiedCommit(msg MessageCertifiedCommit[RI], sender commontypes.OracleID) {
	if repatt.finalized[msg.CertifiedCommit.SeqNr] == nil {
		repatt.logger.Warn("dropping MessageCertifiedCommit for unknown seqNr", commontypes.LogFields{
			"seqNr":  msg.CertifiedCommit.SeqNr,
			"sender": sender,
		})
		return
	}

	senderSigs := repatt.finalized[msg.CertifiedCommit.SeqNr].signatures[sender]
	requestedOutcome := senderSigs != nil && senderSigs.requestedOutcome
	suppliedOutcome := senderSigs != nil && senderSigs.suppliedOutcome
	if !(requestedOutcome && !suppliedOutcome) {
		repatt.logger.Warn("dropping MessageCertifiedCommit for sender who doesn't have pending request", commontypes.LogFields{
			"seqNr":            msg.CertifiedCommit.SeqNr,
			"sender":           sender,
			"requestedOutcome": requestedOutcome,
			"suppliedOutcome":  suppliedOutcome,
		})
		return
	}

	senderSigs.suppliedOutcome = true

	if repatt.finalized[msg.CertifiedCommit.SeqNr].certifiedCommit != nil {
		repatt.logger.Debug("dropping redundant MessageCertifiedCommit", commontypes.LogFields{
			"seqNr":  msg.CertifiedCommit.SeqNr,
			"sender": sender,
		})
		return
	}

	if err := msg.CertifiedCommit.Verify(repatt.config.ConfigDigest, repatt.config.OracleIdentities, repatt.config.ByzQuorumSize()); err != nil {
		repatt.logger.Warn("dropping MessageCertifiedCommit with invalid certified commit", commontypes.LogFields{
			"seqNr":  msg.CertifiedCommit.SeqNr,
			"sender": sender,
		})
		return
	}

	repatt.logger.Debug("triggering eventDeliver based on valid MessageCertifiedCommit", commontypes.LogFields{
		"seqNr":  msg.CertifiedCommit.SeqNr,
		"sender": sender,
	})

	repatt.eventCommittedOutcome(EventCommittedOutcome[RI]{msg.CertifiedCommit})
}

func (repatt *reportAttestationState[RI]) tryRequestCertifiedCommit(seqNr uint64) {
	candidates := make([]commontypes.OracleID, 0, repatt.config.N())
	for signer, sig := range repatt.finalized[seqNr].signatures {
		if sig.requestedOutcome {
			continue
		}
		candidates = append(candidates, signer)
	}

	if len(candidates) == 0 {

		return
	}

	randomOracle := candidates[rand.Intn(len(candidates))]
	repatt.finalized[seqNr].signatures[randomOracle].requestedOutcome = true
	repatt.logger.Debug("sending MessageCertifiedCommitRequest", commontypes.LogFields{
		"seqNr": seqNr,
		"to":    randomOracle,
	})
	repatt.netSender.SendTo(MessageCertifiedCommitRequest[RI]{seqNr}, randomOracle)
	repatt.scheduler.ScheduleDelay(EventMissingOutcome[RI]{seqNr}, deltaRequestCertifiedCommit)
}

func (repatt *reportAttestationState[RI]) tryComplete(seqNr uint64) {
	if repatt.finalized[seqNr].complete {
		repatt.logger.Debug("cannot complete, already completed", commontypes.LogFields{
			"seqNr": seqNr,
		})
		return
	}

	if len(repatt.finalized[seqNr].reportsWithInfo) == 0 {
		if len(repatt.finalized[seqNr].signatures) <= repatt.config.F {
			repatt.logger.Debug("cannot complete, missing reports and signatures", commontypes.LogFields{
				"seqNr": seqNr,
			})
		} else if !repatt.finalized[seqNr].startedFetch {
			repatt.finalized[seqNr].startedFetch = true
			repatt.tryRequestCertifiedCommit(seqNr)
		}
		return
	}

	reportsWithInfo := repatt.finalized[seqNr].reportsWithInfo
	goodSigs := 0
	var aossPerReport [][]types.AttributedOnchainSignature = make([][]types.AttributedOnchainSignature, len(reportsWithInfo))
	for signer, sig := range repatt.finalized[seqNr].signatures {
		if sig.validSignatures == nil {
			validSignatures := repatt.verifySignatures(repatt.config.OracleIdentities[signer].OnchainPublicKey, seqNr, reportsWithInfo, sig.signatures)
			sig.validSignatures = &validSignatures
		}
		if sig.validSignatures != nil && *sig.validSignatures {
			goodSigs++

			for i := range reportsWithInfo {
				aossPerReport[i] = append(aossPerReport[i], types.AttributedOnchainSignature{sig.signatures[i], signer})
			}
		}
		if goodSigs > repatt.config.F {
			break
		}
	}

	if goodSigs <= repatt.config.F {
		repatt.logger.Debug("cannot complete, insufficient number of signatures", commontypes.LogFields{
			"seqNr":    seqNr,
			"goodSigs": goodSigs,
		})
		return
	}

	repatt.finalized[seqNr].complete = true

	repatt.logger.Info("🚀 Ready to broadcast", commontypes.LogFields{
		"seqNr":   seqNr,
		"reports": len(reportsWithInfo),
	})

	for i := range reportsWithInfo {
		select {
		case repatt.chReportAttestationToTransmission <- EventAttestedReport[RI]{
			seqNr,
			i,
			AttestedReportMany[RI]{
				reportsWithInfo[i],
				aossPerReport[i],
			},
		}:
		case <-repatt.ctx.Done():
		}
	}

	repatt.reap()
}

func (repatt *reportAttestationState[RI]) verifySignatures(publicKey types.OnchainPublicKey, seqNr uint64, reportsWithInfo []ocr3types.ReportWithInfo[RI], signatures [][]byte) bool {
	if len(reportsWithInfo) != len(signatures) {
		return false
	}

	n := runtime.GOMAXPROCS(0)
	if (len(reportsWithInfo)+3)/4 < n {
		n = (len(reportsWithInfo) + 3) / 4
	}

	var wg sync.WaitGroup
	wg.Add(n)

	var mutex sync.Mutex
	allValid := true

	for k := 0; k < n; k++ {
		k := k

		go func() {
			defer wg.Done()
			for i := k; i < len(reportsWithInfo); i += n {
				if i%n != k {
					panic("bug")
				}

				mutex.Lock()
				allValidCopy := allValid
				mutex.Unlock()

				if !allValidCopy {
					return
				}

				if !repatt.contractSigner.Verify(publicKey, repatt.config.ConfigDigest, seqNr, reportsWithInfo[i], signatures[i]) {
					mutex.Lock()
					allValid = false
					mutex.Unlock()
					return
				}
			}
		}()
	}

	wg.Wait()

	return allValid
}

func (repatt *reportAttestationState[RI]) eventCommittedOutcome(ev EventCommittedOutcome[RI]) {
	if repatt.finalized[ev.CertifiedCommit.SeqNr] != nil && repatt.finalized[ev.CertifiedCommit.SeqNr].reportsWithInfo != nil {
		repatt.logger.Debug("Skipping delivery of already delivered outcome", commontypes.LogFields{
			"seqNr": ev.CertifiedCommit.SeqNr,
		})
		return
	}

	reportsWithInfo, err := repatt.reportingPlugin.Reports(ev.CertifiedCommit.SeqNr, ev.CertifiedCommit.Outcome)
	if err != nil {
		repatt.logger.Error("ReportingPlugin.Reports failed", commontypes.LogFields{
			"seqNr": ev.CertifiedCommit.SeqNr,
			"error": err,
		})
		return
	}

	if reportsWithInfo == nil {
		repatt.logger.Info("ReportingPlugin.Reports returned no reports, skipping", commontypes.LogFields{
			"seqNr": ev.CertifiedCommit.SeqNr,
		})
		return
	}

	var sigs [][]byte
	for i, reportWithInfo := range reportsWithInfo {
		sig, err := repatt.contractSigner.Sign(repatt.config.ConfigDigest, ev.CertifiedCommit.SeqNr, reportWithInfo)
		if err != nil {
			repatt.logger.Error("Error while signing report", commontypes.LogFields{
				"seqNr": ev.CertifiedCommit.SeqNr,
				"index": i,
				"error": err,
			})
			return
		}
		sigs = append(sigs, sig)
	}

	if _, ok := repatt.finalized[ev.CertifiedCommit.SeqNr]; !ok {
		repatt.finalized[ev.CertifiedCommit.SeqNr] = &finalizationRound[RI]{
			&ev.CertifiedCommit,
			reportsWithInfo,
			map[commontypes.OracleID]*reportSignatures{},
			false,
			false,
		}
	} else {
		repatt.finalized[ev.CertifiedCommit.SeqNr].certifiedCommit = &ev.CertifiedCommit
		repatt.finalized[ev.CertifiedCommit.SeqNr].reportsWithInfo = reportsWithInfo
	}

	if repatt.finalizedHighestSeqNr < ev.CertifiedCommit.SeqNr {
		repatt.finalizedHighestSeqNr = ev.CertifiedCommit.SeqNr
	}

	repatt.logger.Debug("Broadcasting MessageReportSignatures", commontypes.LogFields{
		"seqNr": ev.CertifiedCommit.SeqNr,
	})

	repatt.netSender.Broadcast(MessageReportSignatures[RI]{
		ev.CertifiedCommit.SeqNr,
		sigs,
	})

	// no need to call tryComplete since receipt of our own MessageReportSignatures will do so
}

// func (repatt *reportAttestationState[RI]) finalize(msg MessageReportSignatures) {
// 	repatt.logger.Debug("finalizing report", commontypes.LogFields{
// 		"epoch": msg.Epoch,
// 		"round": msg.Round,
// 	})

// 	epochRound := EpochRound{msg.Epoch, msg.Round}

// 	repatt.finalized[epochRound] = struct{}{}
// 	if repatt.finalizedLatest.Less(epochRound) {
// 		repatt.finalizedLatest = epochRound
// 	}

// 	repatt.netSender.Broadcast(MessageReportSignaturesEcho{msg}) // send [ FINALECHO, e, r, O] to all p_j ∈ P

// 	select {
// 	case repatt.chReportAttestationToTransmission <- EventTransmit(msg):
// 	case <-repatt.ctx.Done():
// 	}

// 	repatt.reap()
// }

func (repatt *reportAttestationState[RI]) isExpired(seqNr uint64) bool {
	highest := repatt.finalizedHighestSeqNr
	expired := uint64(0)
	expirationAgeRounds := uint64(repatt.expirationAgeRounds())
	if highest > expirationAgeRounds {
		expired = highest - expirationAgeRounds
	}
	return seqNr <= expired
}

// reap expired entries from repatt.finalized to prevent unbounded state growth
func (repatt *reportAttestationState[RI]) reap() {
	if len(repatt.finalized) <= 2*repatt.expirationAgeRounds() {
		return
	}
	// A long time ago in a galaxy far, far away, Go used to leak memory when
	// repeatedly adding and deleting from the same map without ever exceeding
	// some maximum length. Fortunately, this is no longer the case
	// https://go-review.googlesource.com/c/go/+/25049/
	for seqNr := range repatt.finalized {
		if repatt.isExpired(seqNr) {
			delete(repatt.finalized, seqNr)
		}
	}
}

// The age (denoted in rounds) after which a report is considered expired and
// will automatically be dropped
func (repatt *reportAttestationState[RI]) expirationAgeRounds() int {
	// number of rounds in a window of duration expirationAgeDuration
	age := math.Ceil(expirationAgeDuration.Seconds() / repatt.config.DeltaRound.Seconds())

	if age < float64(minExpirationAgeRounds) {
		age = float64(minExpirationAgeRounds)
	}
	if math.IsNaN(age) || age > float64(maxExpirationAgeRounds) {
		age = float64(maxExpirationAgeRounds)
	}

	return int(age)
}

func newReportAttestationState[RI any](
	ctx context.Context,

	chNetToReportAttestation <-chan MessageToReportAttestationWithSender[RI],
	chReportAttestationToTransmission chan<- EventToTransmission[RI],
	chOutcomeGenerationToReportAttestation <-chan EventToReportAttestation[RI],
	config ocr3config.SharedConfig,
	contractSigner ocr3types.OnchainKeyring[RI],
	contractTransmitter ocr3types.ContractTransmitter[RI],
	logger loghelper.LoggerWithContext,
	netSender NetworkSender[RI],
	reportingPlugin ocr3types.OCR3Plugin[RI],
) *reportAttestationState[RI] {
	return &reportAttestationState[RI]{
		ctx,

		chNetToReportAttestation,
		chReportAttestationToTransmission,
		chOutcomeGenerationToReportAttestation,
		config,
		contractSigner,
		contractTransmitter,
		logger.MakeUpdated(commontypes.LogFields{"proto": "repatt"}),
		netSender,
		reportingPlugin,

		scheduler.NewScheduler[EventMissingOutcome[RI]](),
		map[uint64]*finalizationRound[RI]{},
		0,
	}
}

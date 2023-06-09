package protocol

import (
	"time"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

const ReportingPluginTimeoutWarningGracePeriod = 100 * time.Millisecond

type Timestamp struct {
	ConfigDigest types.ConfigDigest
	Epoch        uint64
}

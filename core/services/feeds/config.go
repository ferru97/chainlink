package feeds

import (
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/store/models"
)

//go:generate mockery --name Config --output ./mocks/ --case=underscore

type Config interface {
	ChainID() *big.Int
	Dev() bool
	FeatureOffchainReporting(logger.L) bool
	DefaultHTTPTimeout(logger.L) models.Duration
	OCRBlockchainTimeout(logger.L) time.Duration
	OCRContractConfirmations() uint16
	OCRContractPollInterval(logger.Logger) time.Duration
	OCRContractSubscribeInterval(logger.L) time.Duration
	OCRContractTransmitterTransmitTimeout() time.Duration
	OCRDatabaseTimeout() time.Duration
	OCRObservationTimeout(logger.L) time.Duration
	OCRObservationGracePeriod() time.Duration
	LogSQL() bool
}

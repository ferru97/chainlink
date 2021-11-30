package offchainreporting

import (
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/job"
	ocrtypes "github.com/smartcontractkit/libocr/offchainreporting/types"
)

func NewLocalConfig(cfg ValidationConfig, spec job.OffchainReportingOracleSpec, lggr logger.Logger) ocrtypes.LocalConfig {
	concreteSpec := job.LoadEnvConfigVarsLocalOCR(cfg, spec, lggr)
	lc := ocrtypes.LocalConfig{
		BlockchainTimeout:                      concreteSpec.BlockchainTimeout.Duration(),
		ContractConfigConfirmations:            concreteSpec.ContractConfigConfirmations,
		SkipContractConfigConfirmations:        cfg.ChainType().IsL2(),
		ContractConfigTrackerPollInterval:      concreteSpec.ContractConfigTrackerPollInterval.Duration(),
		ContractConfigTrackerSubscribeInterval: concreteSpec.ContractConfigTrackerSubscribeInterval.Duration(),
		ContractTransmitterTransmitTimeout:     cfg.OCRContractTransmitterTransmitTimeout(),
		DatabaseTimeout:                        concreteSpec.DatabaseTimeout.Duration(),
		DataSourceTimeout:                      concreteSpec.ObservationTimeout.Duration(),
		DataSourceGracePeriod:                  cfg.OCRObservationGracePeriod(),
	}
	if cfg.Dev() {
		// Skips config validation so we can use any config parameters we want.
		// For example to lower contractConfigTrackerPollInterval to speed up tests.
		lc.DevelopmentMode = ocrtypes.EnableDangerousDevelopmentMode
	}
	return lc
}

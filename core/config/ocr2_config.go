package config

import (
	"time"

	"github.com/smartcontractkit/chainlink/core/logger"

	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/store/models"
)

type OCR2Config interface {
	// OCR2 config, can override in jobs, all chains
	GlobalOCR2ContractConfirmations(logger.L) (uint16, bool)
	OCR2ContractTransmitterTransmitTimeout(logger.L) time.Duration
	OCR2BlockchainTimeout(logger.L) time.Duration
	OCR2DatabaseTimeout(logger.L) time.Duration
	OCR2ContractPollInterval(logger.L) time.Duration
	OCR2ContractSubscribeInterval(logger.L) time.Duration
	OCR2MonitoringEndpoint() string
	OCR2KeyBundleID() (string, error)
	// OCR2 config, cannot override in jobs
	OCR2TraceLogging() bool
}

func (c *generalConfig) GlobalOCR2ContractConfirmations(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("OCR2ContractConfirmations"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}

func (c *generalConfig) OCR2ContractPollInterval(lggr logger.L) time.Duration {
	return c.getDuration("OCR2ContractPollInterval", lggr)
}

func (c *generalConfig) OCR2ContractSubscribeInterval(lggr logger.L) time.Duration {
	return c.getDuration("OCR2ContractSubscribeInterval", lggr)
}

func (c *generalConfig) OCR2ContractTransmitterTransmitTimeout(lggr logger.L) time.Duration {
	return c.getWithFallback("OCR2ContractTransmitterTransmitTimeout", ParseDuration, lggr).(time.Duration)
}

func (c *generalConfig) OCR2BlockchainTimeout(lggr logger.L) time.Duration {
	return c.getDuration("OCR2BlockchainTimeout", lggr)
}

func (c *generalConfig) OCR2DatabaseTimeout(lggr logger.L) time.Duration {
	return c.getWithFallback("OCR2DatabaseTimeout", ParseDuration, lggr).(time.Duration)
}

func (c *generalConfig) OCR2MonitoringEndpoint() string {
	return c.viper.GetString(EnvVarName("OCR2MonitoringEndpoint"))
}

func (c *generalConfig) OCR2KeyBundleID() (string, error) {
	kbStr := c.viper.GetString(EnvVarName("OCR2KeyBundleID"))
	if kbStr != "" {
		_, err := models.Sha256HashFromHex(kbStr)
		if err != nil {
			return "", errors.Wrapf(ErrInvalid, "OCR_KEY_BUNDLE_ID is an invalid sha256 hash hex string %v", err)
		}
	}
	return kbStr, nil
}

func (c *generalConfig) OCR2TraceLogging() bool {
	return c.viper.GetBool(EnvVarName("OCRTraceLogging"))
}

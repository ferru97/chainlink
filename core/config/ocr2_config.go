package config

import (
	"time"

	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/store/models"
)

type OCR2Config interface {
	// OCR2 config, can override in jobs, all chains
	GlobalOCR2ContractConfirmations() (uint16, bool)
	OCR2ContractTransmitterTransmitTimeout() time.Duration
	OCR2BlockchainTimeout() time.Duration
	OCR2DatabaseTimeout() time.Duration
	OCR2ContractPollInterval() time.Duration
	OCR2ContractSubscribeInterval() time.Duration
	OCR2MonitoringEndpoint() string
	OCR2KeyBundleID() (string, error)
	// OCR2 config, cannot override in jobs
	OCR2TraceLogging() bool
}

func (c *generalConfig) GlobalOCR2ContractConfirmations() (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("OCR2ContractConfirmations"), ParseUint16)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}

func (c *generalConfig) OCR2ContractPollInterval() time.Duration {
	return c.getDuration("OCR2ContractPollInterval")
}

func (c *generalConfig) OCR2ContractSubscribeInterval() time.Duration {
	return c.getDuration("OCR2ContractSubscribeInterval")
}

func (c *generalConfig) OCR2ContractTransmitterTransmitTimeout() time.Duration {
	return c.getWithFallback("OCR2ContractTransmitterTransmitTimeout", ParseDuration).(time.Duration)
}

func (c *generalConfig) OCR2BlockchainTimeout() time.Duration {
	return c.getDuration("OCR2BlockchainTimeout")
}

func (c *generalConfig) OCR2DatabaseTimeout() time.Duration {
	return c.getWithFallback("OCR2DatabaseTimeout", ParseDuration).(time.Duration)
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

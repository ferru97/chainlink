package config

import (
	"time"

	"github.com/smartcontractkit/chainlink/core/logger"

	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/ethkey"
	"github.com/smartcontractkit/chainlink/core/store/models"
)

type OCR1Config interface {
	// OCR1 config, can override in jobs, only ethereum.
	GlobalOCRContractConfirmations(logger.L) (uint16, bool)
	GlobalOCRContractTransmitterTransmitTimeout(logger.L) (time.Duration, bool)
	GlobalOCRDatabaseTimeout(logger.L) (time.Duration, bool)
	GlobalOCRObservationGracePeriod(logger.L) (time.Duration, bool)
	OCRBlockchainTimeout(logger.L) time.Duration
	OCRContractPollInterval(logger.L) time.Duration
	OCRContractSubscribeInterval(logger.L) time.Duration
	OCRMonitoringEndpoint() string
	OCRKeyBundleID() (string, error)
	OCRObservationTimeout(logger.L) time.Duration
	OCRSimulateTransactions() bool
	OCRTransmitterAddress() (ethkey.EIP55Address, error) // OCR2 can support non-evm changes
	// OCR1 config, cannot override in jobs
	OCRTraceLogging() bool
	OCRDefaultTransactionQueueDepth() uint32
}

func (c *generalConfig) getDuration(field string, lggr logger.L) time.Duration {
	return c.getWithFallback(field, ParseDuration, lggr).(time.Duration)
}

func (c *generalConfig) GlobalOCRContractConfirmations(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("OCRContractConfirmations"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}

func (c *generalConfig) GlobalOCRObservationGracePeriod(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("OCRObservationGracePeriod"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}

func (c *generalConfig) GlobalOCRContractTransmitterTransmitTimeout(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("OCRContractTransmitterTransmitTimeout"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}

func (c *generalConfig) GlobalOCRDatabaseTimeout(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("OCRDatabaseTimeout"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}

func (c *generalConfig) OCRContractPollInterval(lggr logger.L) time.Duration {
	return c.getDuration("OCRContractPollInterval", lggr)
}

func (c *generalConfig) OCRContractSubscribeInterval(lggr logger.L) time.Duration {
	return c.getDuration("OCRContractSubscribeInterval", lggr)
}

func (c *generalConfig) OCRBlockchainTimeout(lggr logger.L) time.Duration {
	return c.getDuration("OCRBlockchainTimeout", lggr)
}

func (c *generalConfig) OCRMonitoringEndpoint() string {
	return c.viper.GetString(EnvVarName("OCRMonitoringEndpoint"))
}

func (c *generalConfig) OCRKeyBundleID() (string, error) {
	kbStr := c.viper.GetString(EnvVarName("OCRKeyBundleID"))
	if kbStr != "" {
		_, err := models.Sha256HashFromHex(kbStr)
		if err != nil {
			return "", errors.Wrapf(ErrInvalid, "OCR_KEY_BUNDLE_ID is an invalid sha256 hash hex string %v", err)
		}
	}
	return kbStr, nil
}

// OCRDefaultTransactionQueueDepth controls the queue size for DropOldestStrategy in OCR
// Set to 0 to use SendEvery strategy instead
func (c *generalConfig) OCRDefaultTransactionQueueDepth() uint32 {
	return c.viper.GetUint32(EnvVarName("OCRDefaultTransactionQueueDepth"))
}

// OCRTraceLogging determines whether OCR logs at TRACE level are enabled. The
// option to turn them off is given because they can be very verbose
func (c *generalConfig) OCRTraceLogging() bool {
	return c.viper.GetBool(EnvVarName("OCRTraceLogging"))
}

func (c *generalConfig) OCRObservationTimeout(lggr logger.L) time.Duration {
	return c.getDuration("OCRObservationTimeout", lggr)
}

// OCRSimulateTransactions enables using eth_call transaction simulation before
// sending when set to true
func (c *generalConfig) OCRSimulateTransactions() bool {
	return c.viper.GetBool(EnvVarName("OCRSimulateTransactions"))
}

func (c *generalConfig) OCRTransmitterAddress() (ethkey.EIP55Address, error) {
	taStr := c.viper.GetString(EnvVarName("OCRTransmitterAddress"))
	if taStr != "" {
		ta, err := ethkey.NewEIP55Address(taStr)
		if err != nil {
			return "", errors.Wrapf(ErrInvalid, "OCR_TRANSMITTER_ADDRESS is invalid EIP55 %v", err)
		}
		return ta, nil
	}
	return "", errors.Wrap(ErrUnset, "OCR_TRANSMITTER_ADDRESS env var is not set")
}

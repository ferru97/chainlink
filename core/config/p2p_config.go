package config

import (
	"time"

	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/p2pkey"
	ocrnetworking "github.com/smartcontractkit/libocr/networking"
)

type P2PNetworking interface {
	P2PNetworkingStack() (ocrnetworking.NetworkingStack, error)
	P2PNetworkingStackRaw() string
	P2PPeerID() (p2pkey.PeerID, error)
	P2PPeerIDRaw() string
	P2PIncomingMessageBufferSize(logger.L) int
	P2POutgoingMessageBufferSize(logger.L) int
	P2PDeprecated
}

// P2PNetworkingStack returns the preferred networking stack for libocr
func (c *generalConfig) P2PNetworkingStack() (n ocrnetworking.NetworkingStack, err error) {
	str := c.P2PNetworkingStackRaw()
	err = n.UnmarshalText([]byte(str))
	if err != nil {
		err = errors.Wrapf(err, "P2PNetworkingStack failed to unmarshal '%s'", str)
	}
	return
}

// P2PNetworkingStackRaw returns the raw string passed as networking stack
func (c *generalConfig) P2PNetworkingStackRaw() string {
	return c.viper.GetString(EnvVarName("P2PNetworkingStack"))
}

// P2PPeerID is the default peer ID that will be used, if not overridden
func (c *generalConfig) P2PPeerID() (p2pkey.PeerID, error) {
	pidStr := c.viper.GetString(EnvVarName("P2PPeerID"))
	if pidStr == "" {
		return "", nil
	}
	var pid p2pkey.PeerID
	if err := pid.UnmarshalText([]byte(pidStr)); err != nil {
		return "", errors.Wrapf(ErrInvalid, "P2P_PEER_ID is invalid %v", err)
	}
	return pid, nil
}

// P2PPeerIDRaw returns the string value of whatever P2P_PEER_ID was set to with no parsing
func (c *generalConfig) P2PPeerIDRaw() string {
	return c.viper.GetString(EnvVarName("P2PPeerID"))
}

func (c *generalConfig) P2PIncomingMessageBufferSize(lggr logger.L) int {
	if c.OCRIncomingMessageBufferSize() != 0 {
		return c.OCRIncomingMessageBufferSize()
	}
	return int(c.getWithFallback("P2PIncomingMessageBufferSize", ParseUint16, lggr).(uint16))
}

func (c *generalConfig) P2POutgoingMessageBufferSize(lggr logger.L) int {
	if c.OCROutgoingMessageBufferSize() != 0 {
		return c.OCRIncomingMessageBufferSize()
	}
	return int(c.getWithFallback("P2PIncomingMessageBufferSize", ParseUint16, lggr).(uint16))
}

type P2PDeprecated interface {
	// DEPRECATED - HERE FOR BACKWARDS COMPATABILITY
	OCRNewStreamTimeout() time.Duration
	OCRBootstrapCheckInterval() time.Duration
	OCRDHTLookupInterval() int
	OCRIncomingMessageBufferSize() int
	OCROutgoingMessageBufferSize() int
}

// DEPRECATED, do not use defaults, use only if specified and the
// newer env vars is not
func (c *generalConfig) OCRBootstrapCheckInterval() time.Duration {
	return c.viper.GetDuration("OCRBootstrapCheckInterval")
}

// DEPRECATED
func (c *generalConfig) OCRDHTLookupInterval() int {
	return c.viper.GetInt("OCRDHTLookupInterval")
}

// DEPRECATED
func (c *generalConfig) OCRNewStreamTimeout() time.Duration {
	return c.viper.GetDuration("OCRNewStreamTimeout")
}

// DEPRECATED
func (c *generalConfig) OCRIncomingMessageBufferSize() int {
	return c.viper.GetInt("OCRIncomingMessageBufferSize")
}

// DEPRECATED
func (c *generalConfig) OCROutgoingMessageBufferSize() int {
	return c.viper.GetInt("OCRIncomingMessageBufferSize")
}

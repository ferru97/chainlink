package configtest

import (
	"time"

	"github.com/smartcontractkit/chainlink/core/logger"

	"github.com/smartcontractkit/chainlink/core/config"
)

var _ config.OCR2Config = &TestGeneralConfig{}

func (c *TestGeneralConfig) OCR2DatabaseTimeout(lggr logger.L) time.Duration {
	if c.Overrides.OCR2DatabaseTimeout != nil {
		return *c.Overrides.OCR2DatabaseTimeout
	}
	return c.GeneralConfig.OCR2DatabaseTimeout(lggr)
}

package job

import (
	"net/url"
	"time"

	"github.com/smartcontractkit/chainlink/core/logger"
)

//go:generate mockery --name Service --output ./mocks/ --case=underscore

type Service interface {
	Start() error
	Close() error
}

type Config interface {
	DatabaseURL() (url.URL, error)
	TriggerFallbackDBPollInterval(logger.L) time.Duration
	LogSQL() bool
}

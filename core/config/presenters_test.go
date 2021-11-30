package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestNewConfigPrinter(t *testing.T) {
	cfg, warns, err := NewGeneralConfig()
	require.NoError(t, err)
	assert.Len(t, warns, 1)
	printer, err := NewConfigPrinter(cfg)
	require.NoError(t, err)
	require.NotNil(t, printer)
}

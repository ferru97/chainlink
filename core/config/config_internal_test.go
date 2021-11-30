package config

import (
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestGeneralConfig_Defaults(t *testing.T) {
	config, warns, err := NewGeneralConfig()
	require.NoError(t, err)
	assert.Len(t, warns, 1)
	assert.Equal(t, uint64(10), config.BlockBackfillDepth(nil))
	assert.Equal(t, new(url.URL), config.BridgeResponseURL(nil))
	chainID, err := config.DefaultChainID()
	require.NoError(t, err)
	require.Nil(t, chainID)
	assert.Equal(t, false, config.EthereumDisabled())
	assert.Equal(t, false, config.FeatureExternalInitiators())
	assert.Equal(t, 15*time.Minute, config.SessionTimeout(nil).Duration())
}

func TestGeneralConfig_GlobalOCRDatabaseTimeout(t *testing.T) {
	t.Setenv(EnvVarName("OCRDatabaseTimeout"), "3s")
	config, warns, err := NewGeneralConfig()
	require.NoError(t, err)
	assert.Len(t, warns, 1)

	timeout, ok := config.GlobalOCRDatabaseTimeout(nil)
	require.True(t, ok)
	require.Equal(t, 3*time.Second, timeout)
}

func TestGeneralConfig_GlobalOCRObservationGracePeriod(t *testing.T) {
	t.Setenv(EnvVarName("OCRObservationGracePeriod"), "3s")
	config, warns, err := NewGeneralConfig()
	require.NoError(t, err)
	assert.Len(t, warns, 1)

	timeout, ok := config.GlobalOCRObservationGracePeriod(nil)
	require.True(t, ok)
	require.Equal(t, 3*time.Second, timeout)
}

func TestGeneralConfig_GlobalOCRContractTransmitterTransmitTimeout(t *testing.T) {
	t.Setenv(EnvVarName("OCRContractTransmitterTransmitTimeout"), "3s")
	config, warns, err := NewGeneralConfig()
	require.NoError(t, err)
	assert.Len(t, warns, 1)

	timeout, ok := config.GlobalOCRContractTransmitterTransmitTimeout(nil)
	require.True(t, ok)
	require.Equal(t, 3*time.Second, timeout)
}

func TestGeneralConfig_sessionSecret(t *testing.T) {
	t.Parallel()
	config, warns, err := NewGeneralConfig()
	require.NoError(t, err)
	assert.Len(t, warns, 1)

	initial, err := config.SessionSecret(nil)
	require.NoError(t, err)
	require.NotEqual(t, "", initial)
	require.NotEqual(t, "clsession_test_secret", initial)

	second, err := config.SessionSecret(nil)
	require.NoError(t, err)
	require.Equal(t, initial, second)
}

func TestConfig_readFromFile(t *testing.T) {
	v := viper.New()
	v.Set("ROOT", "../../tools/clroot/")

	config, warns, err := newGeneralConfigWithViper(v)
	require.NoError(t, err)
	assert.Len(t, warns, 1)
	assert.Equal(t, config.RootDir(nil), "../../tools/clroot/")
	assert.Equal(t, config.Dev(), true)
	assert.Equal(t, config.TLSPort(nil), uint16(0))
}

func TestStore_bigIntParser(t *testing.T) {
	val, err := ParseBigInt("0")
	assert.NoError(t, err)
	assert.Equal(t, new(big.Int).SetInt64(0), val)

	val, err = ParseBigInt("15")
	assert.NoError(t, err)
	assert.Equal(t, new(big.Int).SetInt64(15), val)

	val, err = ParseBigInt("x")
	assert.Error(t, err)
	assert.Nil(t, val)

	val, err = ParseBigInt("")
	assert.Error(t, err)
	assert.Nil(t, val)
}

func TestStore_levelParser(t *testing.T) {
	val, err := ParseLogLevel("ERROR")
	assert.NoError(t, err)
	assert.Equal(t, LogLevel{zapcore.ErrorLevel}, val)

	val, err = ParseLogLevel("")
	assert.NoError(t, err)
	assert.Equal(t, LogLevel{zapcore.InfoLevel}, val)

	val, err = ParseLogLevel("primus sucks")
	assert.Error(t, err)
	assert.Equal(t, val, LogLevel{})
}

func TestStore_urlParser(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{"valid URL", "http://localhost:3000", false},
		{"invalid URL", ":", true},
		{"empty URL", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			i, err := ParseURL(test.input)

			if test.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				w, ok := i.(*url.URL)
				require.True(t, ok)
				assert.Equal(t, test.input, w.String())
			}
		})
	}
}

func TestStore_boolParser(t *testing.T) {
	val, err := ParseBool("true")
	assert.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = ParseBool("false")
	assert.NoError(t, err)
	assert.Equal(t, false, val)

	_, err = ParseBool("")
	assert.Error(t, err)
}

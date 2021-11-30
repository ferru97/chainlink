package config

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"go.uber.org/multierr"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink/core/assets"
	"github.com/smartcontractkit/chainlink/core/chains"
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/static"
	"github.com/smartcontractkit/chainlink/core/store/dialects"
	"github.com/smartcontractkit/chainlink/core/store/models"
	"github.com/smartcontractkit/chainlink/core/utils"
)

//go:generate mockery --name GeneralConfig --output ./mocks/ --case=underscore

// this permission grants read / write access to file owners only
const readWritePerms = os.FileMode(0600)

var (
	ErrUnset        = errors.New("env var unset")
	ErrInvalid      = errors.New("env var invalid")
	DefaultLogLevel = LogLevel{zapcore.InfoLevel}

	configFileNotFoundError = reflect.TypeOf(viper.ConfigFileNotFoundError{})
)

// A logger.L may be optionally included to report invalid values
type GeneralOnlyConfig interface {
	Validate() (warns []string, err error)

	SetLogLevel(lvl zapcore.Level) error
	SetLogSQL(logSQL bool)

	AdminCredentialsFile(logger.L) string
	AllowOrigins() string
	AuthenticatedRateLimit() int64
	AuthenticatedRateLimitPeriod(logger.L) models.Duration
	AutoPprofEnabled() bool
	AutoPprofProfileRoot(logger.L) string
	AutoPprofPollInterval(logger.L) models.Duration
	AutoPprofGatherDuration(logger.L) models.Duration
	AutoPprofGatherTraceDuration(logger.L) models.Duration
	AutoPprofMaxProfileSize(logger.L) utils.FileSize
	AutoPprofCPUProfileRate() int
	AutoPprofMemProfileRate() int
	AutoPprofBlockProfileRate() int
	AutoPprofMutexProfileFraction() int
	AutoPprofMemThreshold(logger.L) utils.FileSize
	AutoPprofGoroutineThreshold() int
	BlockBackfillDepth(logger.L) uint64
	BlockBackfillSkip(logger.L) bool
	BridgeResponseURL(logger.L) *url.URL
	CertFile(logger.L) string
	ClientNodeURL() string
	DatabaseBackupDir() string
	DatabaseBackupFrequency(logger.L) time.Duration
	DatabaseBackupMode(logger.L) DatabaseBackupMode
	DatabaseBackupURL() (*url.URL, error)
	DatabaseListenerMaxReconnectDuration(logger.L) time.Duration
	DatabaseListenerMinReconnectInterval(logger.L) time.Duration
	DatabaseLockingMode(logger.L) string
	DatabaseURL() (url.URL, error)
	DefaultChainID() (*big.Int, error)
	DefaultHTTPAllowUnrestrictedNetworkAccess() bool
	DefaultHTTPLimit() int64
	DefaultHTTPTimeout(logger.L) models.Duration
	DefaultMaxHTTPAttempts(logger.L) uint
	Dev() bool
	EVMDisabled() bool
	EthereumDisabled() bool
	EthereumHTTPURL() (*url.URL, error)
	EthereumSecondaryURLs() ([]url.URL, error)
	EthereumURL() string
	ExplorerAccessKey() string
	ExplorerSecret() string
	ExplorerURL(logger.L) *url.URL
	FMDefaultTransactionQueueDepth() uint32
	FMSimulateTransactions() bool
	FeatureExternalInitiators() bool
	FeatureOffchainReporting(logger.L) bool
	FeatureOffchainReporting2(logger.L) bool
	FeatureUICSAKeys(logger.L) bool
	FeatureUIFeedsManager(logger.L) bool
	GetAdvisoryLockIDConfiguredOrDefault() int64
	GetDatabaseDialectConfiguredOrDefault() dialects.DialectName
	GlobalLockRetryInterval(logger.L) models.Duration
	HTTPServerWriteTimeout(logger.L) time.Duration
	InsecureFastScrypt() bool
	InsecureSkipVerify() bool
	JSONConsole() bool
	JobPipelineMaxRunDuration(logger.L) time.Duration
	JobPipelineReaperInterval(logger.L) time.Duration
	JobPipelineReaperThreshold(logger.L) time.Duration
	JobPipelineResultWriteQueueDepth(logger.L) uint64
	KeeperDefaultTransactionQueueDepth() uint32
	KeeperGasPriceBufferPercent() uint32
	KeeperGasTipCapBufferPercent() uint32
	KeeperMaximumGracePeriod() int64
	KeeperRegistryCheckGasOverhead(logger.L) uint64
	KeeperRegistryPerformGasOverhead(logger.L) uint64
	KeeperRegistrySyncInterval(logger.L) time.Duration
	KeeperRegistrySyncUpkeepQueueSize(logger.L) uint32
	KeyFile(logger.L) string
	LeaseLockRefreshInterval(logger.L) time.Duration
	LeaseLockDuration(logger.L) time.Duration
	LogLevel() zapcore.Level
	DefaultLogLevel() zapcore.Level
	LogSQLMigrations() bool
	LogSQL() bool
	LogToDisk() bool
	LogUnixTimestamps() bool
	MigrateDatabase() bool
	ORMMaxIdleConns(logger.L) int
	ORMMaxOpenConns(logger.L) int
	Port(logger.L) uint16
	RPID() string
	RPOrigin() string
	ReaperExpiration(logger.L) models.Duration
	ReplayFromBlock() int64
	RootDir(logger.L) string
	SecureCookies() bool
	SessionOptions() sessions.Options
	SessionSecret(logger.L) ([]byte, error)
	SessionTimeout(logger.L) models.Duration
	StatsPusherLogging(logger.L) bool
	TLSCertPath() string
	TLSDir(logger.L) string
	TLSHost() string
	TLSKeyPath() string
	TLSPort(logger.L) uint16
	TLSRedirect() bool
	TelemetryIngressLogging(logger.L) bool
	TelemetryIngressServerPubKey() string
	TelemetryIngressURL(logger.L) *url.URL
	TriggerFallbackDBPollInterval(logger.L) time.Duration
	UnAuthenticatedRateLimit() int64
	UnAuthenticatedRateLimitPeriod(logger.L) models.Duration
	UseLegacyEthEnvVars() bool
}

// GlobalConfig holds global ENV overrides for EVM chains
// If set the global ENV will override everything
// The second bool indicates if it is set or not
// A logger.L may be optionally included to report invalid values
type GlobalConfig interface {
	GlobalBalanceMonitorEnabled(logger.L) (bool, bool)
	GlobalBlockEmissionIdleWarningThreshold(logger.L) (time.Duration, bool)
	GlobalBlockHistoryEstimatorBatchSize(logger.L) (uint32, bool)
	GlobalBlockHistoryEstimatorBlockDelay(logger.L) (uint16, bool)
	GlobalBlockHistoryEstimatorBlockHistorySize(logger.L) (uint16, bool)
	GlobalBlockHistoryEstimatorTransactionPercentile(logger.L) (uint16, bool)
	GlobalEthTxReaperInterval(logger.L) (time.Duration, bool)
	GlobalEthTxReaperThreshold(logger.L) (time.Duration, bool)
	GlobalEthTxResendAfterThreshold(logger.L) (time.Duration, bool)
	GlobalEvmDefaultBatchSize(logger.L) (uint32, bool)
	GlobalEvmEIP1559DynamicFees(logger.L) (bool, bool)
	GlobalEvmFinalityDepth(logger.L) (uint32, bool)
	GlobalEvmGasBumpPercent(logger.L) (uint16, bool)
	GlobalEvmGasBumpThreshold(logger.L) (uint64, bool)
	GlobalEvmGasBumpTxDepth(logger.L) (uint16, bool)
	GlobalEvmGasBumpWei(logger.L) (*big.Int, bool)
	GlobalEvmGasLimitDefault(logger.L) (uint64, bool)
	GlobalEvmGasLimitMultiplier(logger.L) (float32, bool)
	GlobalEvmGasLimitTransfer(logger.L) (uint64, bool)
	GlobalEvmGasPriceDefault(logger.L) (*big.Int, bool)
	GlobalEvmGasTipCapDefault(logger.L) (*big.Int, bool)
	GlobalEvmGasTipCapMinimum(logger.L) (*big.Int, bool)
	GlobalEvmHeadTrackerHistoryDepth(logger.L) (uint32, bool)
	GlobalEvmHeadTrackerMaxBufferSize(logger.L) (uint32, bool)
	GlobalEvmHeadTrackerSamplingInterval(logger.L) (time.Duration, bool)
	GlobalEvmLogBackfillBatchSize(logger.L) (uint32, bool)
	GlobalEvmMaxGasPriceWei(logger.L) (*big.Int, bool)
	GlobalEvmMaxInFlightTransactions(logger.L) (uint32, bool)
	GlobalEvmMaxQueuedTransactions(logger.L) (uint64, bool)
	GlobalEvmMinGasPriceWei(logger.L) (*big.Int, bool)
	GlobalEvmNonceAutoSync(logger.L) (bool, bool)
	GlobalEvmRPCDefaultBatchSize(logger.L) (uint32, bool)
	GlobalFlagsContractAddress() (string, bool)
	GlobalGasEstimatorMode() (string, bool)
	GlobalChainType() (string, bool)
	GlobalLinkContractAddress() (string, bool)
	GlobalMinIncomingConfirmations(logger.L) (uint32, bool)
	GlobalMinRequiredOutgoingConfirmations(logger.L) (uint64, bool)
	GlobalMinimumContractPayment(logger.L) (*assets.Link, bool)

	OCR1Config
	OCR2Config
	P2PNetworking
	P2PV1Networking
	P2PV2Networking
}

type GeneralConfig interface {
	GeneralOnlyConfig
	GlobalConfig
}

// generalConfig holds parameters used by the application which can be overridden by
// setting environment variables.
//
// If you add an entry here which does not contain sensitive information, you
// should also update presenters.ConfigWhitelist and cmd_test.TestClient_RunNodeShowsEnv.
type generalConfig struct {
	viper           *viper.Viper
	secretGenerator SecretGenerator
	randomP2PPort   uint16
	dialect         dialects.DialectName
	advisoryLockID  int64
	logLevel        zapcore.Level
	defaultLogLevel zapcore.Level
	logSQL          bool
	logMutex        sync.RWMutex
}

// NewGeneralConfig returns the config with the environment variables set to their
// respective fields, or their defaults if environment variables are not set.
func NewGeneralConfig() (GeneralConfig, []string, error) {
	v := viper.New()
	c, warns, err := newGeneralConfigWithViper(v)
	if err != nil {
		return nil, nil, err
	}
	c.secretGenerator = FilePersistedSecretGenerator{}
	c.dialect = dialects.Postgres
	return c, warns, nil
}

func newGeneralConfigWithViper(v *viper.Viper) (config *generalConfig, warns []string, err error) {
	schemaT := reflect.TypeOf(ConfigSchema{})
	for index := 0; index < schemaT.NumField(); index++ {
		item := schemaT.FieldByIndex([]int{index})
		name := item.Tag.Get("env")
		def, exists := item.Tag.Lookup("default")
		if exists {
			v.SetDefault(name, def)
		}
		_ = v.BindEnv(name, name)
	}

	config = &generalConfig{
		viper:           v,
		defaultLogLevel: DefaultLogLevel.Level,
	}

	rootDir := config.RootDir(nil)
	if err := utils.EnsureDirAndMaxPerms(rootDir, os.FileMode(0700)); err != nil {
		return nil, nil, errors.Wrapf(err, `Error creating root directory "%s"`, rootDir)
	}

	v.SetConfigName("chainlink")
	v.AddConfigPath(rootDir)
	if err := v.ReadInConfig(); err != nil && reflect.TypeOf(err) != configFileNotFoundError {
		warns = append(warns, fmt.Sprintf("Unable to load config file: %v", err))
	}

	r, err := rand.Int(rand.Reader, big.NewInt(65535-1023))
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected error generating random port: %w", err)
	}
	config.randomP2PPort = uint16(r.Int64() + 1024)
	if !v.IsSet(EnvVarName("P2PListenPort")) {
		warns = append(warns, fmt.Sprintf("P2P_LISTEN_PORT was not set, listening on random port %d. A new random port will be generated on every boot, for stability it is recommended to set P2P_LISTEN_PORT to a fixed value in your environment", config.randomP2PPort))
	}

	if v.IsSet(EnvVarName("LogLevel")) {
		str := v.GetString(EnvVarName("LogLevel"))
		ll, err := ParseLogLevel(str)
		if err != nil {
			warns = append(warns, fmt.Sprintf("error parsing log level: %s, falling back to %s", str, DefaultLogLevel.Level))
		} else {
			config.defaultLogLevel = ll.(LogLevel).Level
		}
	}
	config.logLevel = config.defaultLogLevel
	config.logSQL = viper.GetBool(EnvVarName("LogSQL"))

	return
}

// Validate performs basic sanity checks on config and returns error if any
// misconfiguration would be fatal to the application
func (c *generalConfig) Validate() (warns []string, err error) {
	if c.P2PAnnouncePort() != 0 && c.P2PAnnounceIP() == nil {
		return nil, errors.Errorf("P2P_ANNOUNCE_PORT was given as %v but P2P_ANNOUNCE_IP was unset. You must also set P2P_ANNOUNCE_IP if P2P_ANNOUNCE_PORT is set", c.P2PAnnouncePort())
	}

	if _, exists := os.LookupEnv("MINIMUM_CONTRACT_PAYMENT"); exists {
		return nil, errors.Errorf("MINIMUM_CONTRACT_PAYMENT is deprecated, use MINIMUM_CONTRACT_PAYMENT_LINK_JUELS instead.")
	}

	if _, err := c.OCRKeyBundleID(); errors.Cause(err) == ErrInvalid {
		return nil, err
	}
	if _, err := c.OCRTransmitterAddress(); errors.Cause(err) == ErrInvalid {
		return nil, err
	}
	if peers, err := c.P2PBootstrapPeers(); err == nil {
		for i := range peers {
			if _, err := multiaddr.NewMultiaddr(peers[i]); err != nil {
				return nil, errors.Errorf("p2p bootstrap peer %d is invalid: err %v", i, err)
			}
		}
	}
	if me := c.OCRMonitoringEndpoint(); me != "" {
		if _, err := url.Parse(me); err != nil {
			return nil, errors.Wrapf(err, "invalid monitoring url: %s", me)
		}
	}
	if ct, set := c.GlobalChainType(); set && !chains.ChainType(ct).IsValid() {
		return nil, errors.Errorf("CHAIN_TYPE is invalid: %s", ct)
	}

	if !c.UseLegacyEthEnvVars() {
		if c.EthereumURL() != "" {
			warns = append(warns, "ETH_URL has no effect when USE_LEGACY_ETH_ENV_VARS=false")
		}
		if ethURL, err := c.EthereumHTTPURL(); err != nil {
			return nil, err
		} else if ethURL != nil {
			warns = append(warns, "ETH_HTTP_URL has no effect when USE_LEGACY_ETH_ENV_VARS=false")
		}
		if urls, err := c.EthereumSecondaryURLs(); err != nil {
			return nil, err
		} else if len(urls) > 0 {
			warns = append(warns, "ETH_SECONDARY_URL/ETH_SECONDARY_URLS have no effect when USE_LEGACY_ETH_ENV_VARS=false")
		}
	}
	// Warn on legacy OCR env vars
	if c.OCRDHTLookupInterval() != 0 {
		warns = append(warns, "OCR_DHT_LOOKUP_INTERVAL is deprecated, use P2P_DHT_LOOKUP_INTERVAL instead")
	}
	if c.OCRBootstrapCheckInterval() != 0 {
		warns = append(warns, "OCR_BOOTSTRAP_CHECK_INTERVAL is deprecated, use P2P_BOOTSTRAP_CHECK_INTERVAL instead")
	}
	if c.OCRIncomingMessageBufferSize() != 0 {
		warns = append(warns, "OCR_INCOMING_MESSAGE_BUFFER_SIZE is deprecated, use P2P_INCOMING_MESSAGE_BUFFER_SIZE instead")
	}
	if c.OCROutgoingMessageBufferSize() != 0 {
		warns = append(warns, "OCR_OUTGOING_MESSAGE_BUFFER_SIZE is deprecated, use P2P_OUTGOING_MESSAGE_BUFFER_SIZE instead")
	}
	if c.OCRNewStreamTimeout() != 0 {
		warns = append(warns, "OCR_NEW_STREAM_TIMEOUT is deprecated, use P2P_NEW_STREAM_TIMEOUT instead")
	}

	dbLockingMode := c.DatabaseLockingMode(nil)
	switch dbLockingMode {
	case "dual", "lease", "advisorylock", "none":
	default:
		return nil, errors.Errorf("unrecognised value for DATABASE_LOCKING_MODE: %s (valid options are 'dual', 'lease', 'advisorylock' or 'none')", dbLockingMode)
	}

	if refreshInterval, lockDuration := c.LeaseLockRefreshInterval(nil), c.LeaseLockDuration(nil); refreshInterval > lockDuration/2 {
		return nil, errors.Errorf("LEASE_LOCK_REFRESH_INTERVAL must be less than or equal to half of LEASE_LOCK_DURATION (got LEASE_LOCK_REFRESH_INTERVAL=%d, LEASE_LOCK_DURATION=%d)", refreshInterval, lockDuration)
	}

	return
}

func (c *generalConfig) GetAdvisoryLockIDConfiguredOrDefault() int64 {
	return c.advisoryLockID
}

func (c *generalConfig) GetDatabaseDialectConfiguredOrDefault() dialects.DialectName {
	return c.dialect
}

// AllowOrigins returns the CORS hosts used by the frontend.
func (c *generalConfig) AllowOrigins() string {
	return c.viper.GetString(EnvVarName("AllowOrigins"))
}

// AdminCredentialsFile points to text file containing admin credentials for logging in
func (c *generalConfig) AdminCredentialsFile(lggr logger.L) string {
	fieldName := "AdminCredentialsFile"
	file := c.viper.GetString(EnvVarName(fieldName))
	defaultValue, _ := defaultValue(fieldName)
	if file == defaultValue {
		return filepath.Join(c.RootDir(lggr), "apicredentials")
	}
	return file
}

// AuthenticatedRateLimit defines the threshold to which requests authenticated requests get limited
func (c *generalConfig) AuthenticatedRateLimit() int64 {
	return c.viper.GetInt64(EnvVarName("AuthenticatedRateLimit"))
}

// AuthenticatedRateLimitPeriod defines the period to which authenticated requests get limited
func (c *generalConfig) AuthenticatedRateLimitPeriod(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("AuthenticatedRateLimitPeriod", ParseDuration, lggr).(time.Duration))
}

func (c *generalConfig) AutoPprofEnabled() bool {
	return c.viper.GetBool(EnvVarName("AutoPprofEnabled"))
}

func (c *generalConfig) AutoPprofProfileRoot(lggr logger.L) string {
	root := c.viper.GetString(EnvVarName("AutoPprofProfileRoot"))
	if root == "" {
		return c.RootDir(lggr)
	}
	return root
}

func (c *generalConfig) AutoPprofPollInterval(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("AutoPprofPollInterval", ParseDuration, lggr).(time.Duration))
}

func (c *generalConfig) AutoPprofGatherDuration(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("AutoPprofGatherDuration", ParseDuration, lggr).(time.Duration))
}

func (c *generalConfig) AutoPprofGatherTraceDuration(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("AutoPprofGatherTraceDuration", ParseDuration, lggr).(time.Duration))
}

func (c *generalConfig) AutoPprofMaxProfileSize(lggr logger.L) utils.FileSize {
	return c.getWithFallback("AutoPprofMaxProfileSize", ParseFileSize, lggr).(utils.FileSize)
}

func (c *generalConfig) AutoPprofCPUProfileRate() int {
	return c.viper.GetInt(EnvVarName("AutoPprofCPUProfileRate"))
}

func (c *generalConfig) AutoPprofMemProfileRate() int {
	return c.viper.GetInt(EnvVarName("AutoPprofMemProfileRate"))
}

func (c *generalConfig) AutoPprofBlockProfileRate() int {
	return c.viper.GetInt(EnvVarName("AutoPprofBlockProfileRate"))
}

func (c *generalConfig) AutoPprofMutexProfileFraction() int {
	return c.viper.GetInt(EnvVarName("AutoPprofMutexProfileFraction"))
}

func (c *generalConfig) AutoPprofMemThreshold(lggr logger.L) utils.FileSize {
	return c.getWithFallback("AutoPprofMemThreshold", ParseFileSize, lggr).(utils.FileSize)
}

func (c *generalConfig) AutoPprofGoroutineThreshold() int {
	return c.viper.GetInt(EnvVarName("AutoPprofGoroutineThreshold"))
}

// BlockBackfillDepth specifies the number of blocks before the current HEAD that the
// log broadcaster will try to re-consume logs from
func (c *generalConfig) BlockBackfillDepth(lggr logger.L) uint64 {
	return c.getWithFallback("BlockBackfillDepth", ParseUint64, lggr).(uint64)
}

// BlockBackfillSkip enables skipping of very long log backfills
func (c *generalConfig) BlockBackfillSkip(lggr logger.L) bool {
	return c.getWithFallback("BlockBackfillSkip", ParseBool, lggr).(bool)
}

// BridgeResponseURL represents the URL for bridges to send a response to.
func (c *generalConfig) BridgeResponseURL(lggr logger.L) *url.URL {
	return c.getWithFallback("BridgeResponseURL", ParseURL, lggr).(*url.URL)
}

// ClientNodeURL is the URL of the Ethereum node this Chainlink node should connect to.
func (c *generalConfig) ClientNodeURL() string {
	return c.viper.GetString(EnvVarName("ClientNodeURL"))
}

// FeatureUICSAKeys enables the CSA Keys UI Feature.
func (c *generalConfig) FeatureUICSAKeys(lggr logger.L) bool {
	return c.getWithFallback("FeatureUICSAKeys", ParseBool, lggr).(bool)
}

func (c *generalConfig) FeatureUIFeedsManager(lggr logger.L) bool {
	return c.getWithFallback("FeatureUIFeedsManager", ParseBool, lggr).(bool)
}

func (c *generalConfig) DatabaseListenerMinReconnectInterval(lggr logger.L) time.Duration {
	return c.getWithFallback("DatabaseListenerMinReconnectInterval", ParseDuration, lggr).(time.Duration)
}

func (c *generalConfig) DatabaseListenerMaxReconnectDuration(lggr logger.L) time.Duration {
	return c.getWithFallback("DatabaseListenerMaxReconnectDuration", ParseDuration, lggr).(time.Duration)
}

// DatabaseBackupMode sets the database backup mode
func (c *generalConfig) DatabaseBackupMode(lggr logger.L) DatabaseBackupMode {
	return c.getWithFallback("DatabaseBackupMode", parseDatabaseBackupMode, lggr).(DatabaseBackupMode)
}

// DatabaseBackupFrequency turns on the periodic database backup if set to a positive value
// DatabaseBackupMode must be then set to a value other than "none"
func (c *generalConfig) DatabaseBackupFrequency(lggr logger.L) time.Duration {
	return c.getWithFallback("DatabaseBackupFrequency", ParseDuration, lggr).(time.Duration)
}

// DatabaseBackupURL configures the URL for the database to backup, if it's to be different from the main on
func (c *generalConfig) DatabaseBackupURL() (*url.URL, error) {
	s := c.viper.GetString(EnvVarName("DatabaseBackupURL"))
	if s == "" {
		return nil, nil
	}
	uri, err := url.Parse(s)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid database backup url %s", s)
	}
	return uri, nil
}

// DatabaseBackupDir configures the directory for saving the backup file, if it's to be different from default one located in the RootDir
func (c *generalConfig) DatabaseBackupDir() string {
	return c.viper.GetString(EnvVarName("DatabaseBackupDir"))
}

// GlobalLockRetryInterval represents how long to wait before trying again to get the global advisory lock.
func (c *generalConfig) GlobalLockRetryInterval(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("GlobalLockRetryInterval", ParseDuration, lggr).(time.Duration))
}

// DatabaseURL configures the URL for chainlink to connect to. This must be
// a properly formatted URL, with a valid scheme (postgres://)
func (c *generalConfig) DatabaseURL() (url.URL, error) {
	s := c.viper.GetString(EnvVarName("DatabaseURL"))
	uri, err := url.Parse(s)
	if err != nil {
		return url.URL{}, errors.Wrapf(err, "invalid database url")
	}
	if uri.String() == "" {
		return url.URL{}, errors.New("You must set DATABASE_URL env variable. HINT: If you are running this to set up your local test database, try DATABASE_URL=postgresql://postgres@localhost:5432/chainlink_test?sslmode=disable")
	}
	static.SetConsumerName(uri, "Default", nil)
	return *uri, nil
}

// MigrateDatabase determines whether the database will be automatically
// migrated on application startup if set to true
func (c *generalConfig) MigrateDatabase() bool {
	return c.viper.GetBool(EnvVarName("MigrateDatabase"))
}

// DefaultMaxHTTPAttempts defines the limit for HTTP requests.
func (c *generalConfig) DefaultMaxHTTPAttempts(lggr logger.L) uint {
	return uint(c.getWithFallback("DefaultMaxHTTPAttempts", ParseUint64, lggr).(uint64))
}

// DefaultHTTPLimit defines the size limit for HTTP requests and responses
func (c *generalConfig) DefaultHTTPLimit() int64 {
	return c.viper.GetInt64(EnvVarName("DefaultHTTPLimit"))
}

// DefaultHTTPTimeout defines the default timeout for http requests
func (c *generalConfig) DefaultHTTPTimeout(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("DefaultHTTPTimeout", ParseDuration, lggr).(time.Duration))
}

// DefaultHTTPAllowUnrestrictedNetworkAccess controls whether http requests are unrestricted by default
// It is recommended that this be left disabled
func (c *generalConfig) DefaultHTTPAllowUnrestrictedNetworkAccess() bool {
	return c.viper.GetBool(EnvVarName("DefaultHTTPAllowUnrestrictedNetworkAccess"))
}

// Dev configures "development" mode for chainlink.
func (c *generalConfig) Dev() bool {
	return c.viper.GetBool(EnvVarName("Dev"))
}

// FeatureExternalInitiators enables the External Initiator feature.
func (c *generalConfig) FeatureExternalInitiators() bool {
	return c.viper.GetBool(EnvVarName("FeatureExternalInitiators"))
}

// FeatureOffchainReporting enables the OCR job type.
func (c *generalConfig) FeatureOffchainReporting(lggr logger.L) bool {
	return c.getWithFallback("FeatureOffchainReporting", ParseBool, lggr).(bool)
}

// FeatureOffchainReporting2 enables the OCR2 job type.
func (c *generalConfig) FeatureOffchainReporting2(lggr logger.L) bool {
	return c.getWithFallback("FeatureOffchainReporting2", ParseBool, lggr).(bool)
}

// FMDefaultTransactionQueueDepth controls the queue size for DropOldestStrategy in Flux Monitor
// Set to 0 to use SendEvery strategy instead
func (c *generalConfig) FMDefaultTransactionQueueDepth() uint32 {
	return c.viper.GetUint32(EnvVarName("FMDefaultTransactionQueueDepth"))
}

// FMSimulateTransactions enables using eth_call transaction simulation before
// sending when set to true
func (c *generalConfig) FMSimulateTransactions() bool {
	return c.viper.GetBool(EnvVarName("FMSimulateTransactions"))
}

// EthereumURL represents the URL of the Ethereum node to connect Chainlink to.
func (c *generalConfig) EthereumURL() string {
	return c.viper.GetString(EnvVarName("EthereumURL"))
}

// EthereumHTTPURL is an optional but recommended url that points to the HTTP port of the primary node
func (c *generalConfig) EthereumHTTPURL() (uri *url.URL, err error) {
	urlStr := c.viper.GetString(EnvVarName("EthereumHTTPURL"))
	if urlStr == "" {
		return nil, nil
	}
	uri, err = url.Parse(urlStr)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid Ethereum HTTP URL: %s", urlStr)
	} else if !(uri.Scheme == "http" || uri.Scheme == "https") {
		return nil, fmt.Errorf("invalid Ethereum HTTP URL scheme: %s", urlStr)
	}
	return
}

// EthereumSecondaryURLs is an optional backup RPC URL
// Must be http(s) format
// If specified, transactions will also be broadcast to this ethereum node
func (c *generalConfig) EthereumSecondaryURLs() (urls []url.URL, err error) {
	oldConfig := c.viper.GetString(EnvVarName("EthereumSecondaryURL"))
	newConfig := c.viper.GetString(EnvVarName("EthereumSecondaryURLs"))

	config := ""
	if newConfig != "" {
		config = newConfig
	} else if oldConfig != "" {
		config = oldConfig
	}

	urlStrings := regexp.MustCompile(`\s*[;,]\s*`).Split(config, -1)
	for _, urlString := range urlStrings {
		if urlString == "" {
			continue
		}
		url, err2 := url.Parse(urlString)
		if err2 != nil {
			err = multierr.Append(err, errors.Wrapf(err2, "Invalid Secondary Ethereum URL: %s", urlString))
			continue
		}
		urls = append(urls, *url)
	}

	return
}

// EthereumDisabled will substitute null Eth clients if set
func (c *generalConfig) EthereumDisabled() bool {
	return c.viper.GetBool(EnvVarName("EthereumDisabled"))
}

// EVMDisabled prevents any evm_chains from being loaded at all if set
func (c *generalConfig) EVMDisabled() bool {
	return c.viper.GetBool(EnvVarName("EVMDisabled"))
}

// InsecureFastScrypt causes all key stores to encrypt using "fast" scrypt params instead
// This is insecure and only useful for local testing. DO NOT SET THIS IN PRODUCTION
func (c *generalConfig) InsecureFastScrypt() bool {
	return c.viper.GetBool(EnvVarName("InsecureFastScrypt"))
}

// InsecureSkipVerify disables SSL certificate verification when connection to
// a chainlink client using the remote client, i.e. when executing most remote
// commands in the CLI.
//
// This is mostly useful for people who want to use TLS on localhost.
func (c *generalConfig) InsecureSkipVerify() bool {
	return c.viper.GetBool(EnvVarName("InsecureSkipVerify"))
}

func (c *generalConfig) TriggerFallbackDBPollInterval(lggr logger.L) time.Duration {
	return c.getWithFallback("TriggerFallbackDBPollInterval", ParseDuration, lggr).(time.Duration)
}

// JobPipelineMaxRunDuration is the maximum time that a job run may take
func (c *generalConfig) JobPipelineMaxRunDuration(lggr logger.L) time.Duration {
	return c.getWithFallback("JobPipelineMaxRunDuration", ParseDuration, lggr).(time.Duration)
}

func (c *generalConfig) JobPipelineResultWriteQueueDepth(lggr logger.L) uint64 {
	return c.getWithFallback("JobPipelineResultWriteQueueDepth", ParseUint64, lggr).(uint64)
}

func (c *generalConfig) JobPipelineReaperInterval(lggr logger.L) time.Duration {
	return c.getWithFallback("JobPipelineReaperInterval", ParseDuration, lggr).(time.Duration)
}

func (c *generalConfig) JobPipelineReaperThreshold(lggr logger.L) time.Duration {
	return c.getWithFallback("JobPipelineReaperThreshold", ParseDuration, lggr).(time.Duration)
}

// KeeperRegistryCheckGasOverhead is the amount of extra gas to provide checkUpkeep() calls
// to account for the gas consumed by the keeper registry
func (c *generalConfig) KeeperRegistryCheckGasOverhead(lggr logger.L) uint64 {
	return c.getWithFallback("KeeperRegistryCheckGasOverhead", ParseUint64, lggr).(uint64)
}

// KeeperRegistryPerformGasOverhead is the amount of extra gas to provide performUpkeep() calls
// to account for the gas consumed by the keeper registry
func (c *generalConfig) KeeperRegistryPerformGasOverhead(lggr logger.L) uint64 {
	return c.getWithFallback("KeeperRegistryPerformGasOverhead", ParseUint64, lggr).(uint64)
}

// KeeperDefaultTransactionQueueDepth controls the queue size for DropOldestStrategy in Keeper
// Set to 0 to use SendEvery strategy instead
func (c *generalConfig) KeeperDefaultTransactionQueueDepth() uint32 {
	return c.viper.GetUint32(EnvVarName("KeeperDefaultTransactionQueueDepth"))
}

// KeeperGasPriceBufferPercent adds the specified percentage to the gas price
// used for checking whether to perform an upkeep. Only applies in legacy mode.
func (c *generalConfig) KeeperGasPriceBufferPercent() uint32 {
	return c.viper.GetUint32(EnvVarName("KeeperGasPriceBufferPercent"))
}

// KeeperGasTipCapBufferPercent adds the specified percentage to the gas price
// used for checking whether to perform an upkeep. Only applies in EIP-1559 mode.
func (c *generalConfig) KeeperGasTipCapBufferPercent() uint32 {
	return c.viper.GetUint32(EnvVarName("KeeperGasTipCapBufferPercent"))
}

// KeeperRegistrySyncInterval is the interval in which the RegistrySynchronizer performs a full
// sync of the keeper registry contract it is tracking
func (c *generalConfig) KeeperRegistrySyncInterval(lggr logger.L) time.Duration {
	return c.getWithFallback("KeeperRegistrySyncInterval", ParseDuration, lggr).(time.Duration)
}

// KeeperMaximumGracePeriod is the maximum number of blocks that a keeper will wait after performing
// an upkeep before it resumes checking that upkeep
func (c *generalConfig) KeeperMaximumGracePeriod() int64 {
	return c.viper.GetInt64(EnvVarName("KeeperMaximumGracePeriod"))
}

// KeeperRegistrySyncUpkeepQueueSize represents the maximum number of upkeeps that can be synced in parallel
func (c *generalConfig) KeeperRegistrySyncUpkeepQueueSize(lggr logger.L) uint32 {
	return c.getWithFallback("KeeperRegistrySyncUpkeepQueueSize", ParseUint32, lggr).(uint32)
}

// JSONConsole when set to true causes logging to be made in JSON format
// If set to false, logs in console format
func (c *generalConfig) JSONConsole() bool {
	return c.viper.GetBool(EnvVarName("JSONConsole"))
}

// ExplorerURL returns the websocket URL for this node to push stats to, or nil.
func (c *generalConfig) ExplorerURL(lggr logger.L) *url.URL {
	rval := c.getWithFallback("ExplorerURL", ParseURL, lggr)
	switch t := rval.(type) {
	case nil:
		return nil
	case *url.URL:
		return t
	default:
		panic(fmt.Sprintf("invariant: ExplorerURL returned as type %T", rval))
	}
}

// ExplorerAccessKey returns the access key for authenticating with explorer
func (c *generalConfig) ExplorerAccessKey() string {
	return c.viper.GetString(EnvVarName("ExplorerAccessKey"))
}

// ExplorerSecret returns the secret for authenticating with explorer
func (c *generalConfig) ExplorerSecret() string {
	return c.viper.GetString(EnvVarName("ExplorerSecret"))
}

// TelemetryIngressURL returns the WSRPC URL for this node to push telemetry to, or nil.
func (c *generalConfig) TelemetryIngressURL(lggr logger.L) *url.URL {
	rval := c.getWithFallback("TelemetryIngressURL", ParseURL, lggr)
	switch t := rval.(type) {
	case nil:
		return nil
	case *url.URL:
		return t
	default:
		panic(fmt.Sprintf("invariant: TelemetryIngressURL returned as type %T", rval))
	}
}

// TelemetryIngressServerPubKey returns the public key to authenticate the telemetry ingress server
func (c *generalConfig) TelemetryIngressServerPubKey() string {
	return c.viper.GetString(EnvVarName("TelemetryIngressServerPubKey"))
}

// TelemetryIngressLogging toggles very verbose logging of raw telemetry messages for the TelemetryIngressClient
func (c *generalConfig) TelemetryIngressLogging(lggr logger.L) bool {
	return c.getWithFallback("TelemetryIngressLogging", ParseBool, lggr).(bool)
}

func (c *generalConfig) ORMMaxOpenConns(lggr logger.L) int {
	return int(c.getWithFallback("ORMMaxOpenConns", ParseUint16, lggr).(uint16))
}

func (c *generalConfig) ORMMaxIdleConns(lggr logger.L) int {
	return int(c.getWithFallback("ORMMaxIdleConns", ParseUint16, lggr).(uint16))
}

// LogLevel represents the maximum level of log messages to output.
func (c *generalConfig) LogLevel() zapcore.Level {
	c.logMutex.RLock()
	defer c.logMutex.RUnlock()
	return c.logLevel
}

// DefaultLogLevel returns default log level.
func (c *generalConfig) DefaultLogLevel() zapcore.Level {
	return c.defaultLogLevel
}

// SetLogLevel saves a runtime value for the default logger level
func (c *generalConfig) SetLogLevel(lvl zapcore.Level) error {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	c.logLevel = lvl
	return nil
}

// LogToDisk configures disk preservation of logs.
func (c *generalConfig) LogToDisk() bool {
	return c.viper.GetBool(EnvVarName("LogToDisk"))
}

// LogSQL tells chainlink to log all SQL statements made using the default logger
func (c *generalConfig) LogSQL() bool {
	c.logMutex.RLock()
	defer c.logMutex.RUnlock()
	return c.logSQL
}

// SetLogSQL saves a runtime value for enabling/disabling logging all SQL statements on the default logger
func (c *generalConfig) SetLogSQL(logSQL bool) {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	c.logSQL = logSQL
}

// LogSQLMigrations tells chainlink to log all SQL migrations made using the default logger
func (c *generalConfig) LogSQLMigrations() bool {
	return c.viper.GetBool(EnvVarName("LogSQLMigrations"))
}

// LogUnixTimestamps if set to true will log with timestamp in unix format, otherwise uses ISO8601
func (c *generalConfig) LogUnixTimestamps() bool {
	return c.viper.GetBool(EnvVarName("LogUnixTS"))
}

// Port represents the port Chainlink should listen on for client requests.
func (c *generalConfig) Port(lggr logger.L) uint16 {
	return c.getWithFallback("Port", ParseUint16, lggr).(uint16)
}

// DefaultChainID represents the chain ID which jobs will use if one is not explicitly specified
func (c *generalConfig) DefaultChainID() (*big.Int, error) {
	str := c.viper.GetString(EnvVarName("DefaultChainID"))
	if str != "" {
		v, err := ParseBigInt(str)
		if err != nil {
			return nil, errors.Wrapf(err, "Ignoring invalid value provided for ETH_CHAIN_ID (%s)", str)
		}
		return v.(*big.Int), nil

	}
	return nil, nil
}

func (c *generalConfig) HTTPServerWriteTimeout(lggr logger.L) time.Duration {
	return c.getWithFallback("HTTPServerWriteTimeout", ParseDuration, lggr).(time.Duration)
}

// ReaperExpiration represents
func (c *generalConfig) ReaperExpiration(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("ReaperExpiration", ParseDuration, lggr).(time.Duration))
}

func (c *generalConfig) ReplayFromBlock() int64 {
	return c.viper.GetInt64(EnvVarName("ReplayFromBlock"))
}

// RootDir represents the location on the file system where Chainlink should
// keep its files.
func (c *generalConfig) RootDir(lggr logger.L) string {
	return c.getWithFallback("RootDir", ParseHomeDir, lggr).(string)
}

// RPID Fetches the RPID used for WebAuthn sessions. The RPID value should be the FQDN (localhost)
func (c *generalConfig) RPID() string {
	return c.viper.GetString(EnvVarName("RPID"))
}

// RPOrigin Fetches the RPOrigin used to configure WebAuthn sessions. The RPOrigin valiue should be
// the origin URL where WebAuthn requests initiate (http://localhost:6688/)
func (c *generalConfig) RPOrigin() string {
	return c.viper.GetString(EnvVarName("RPOrigin"))
}

// SecureCookies allows toggling of the secure cookies HTTP flag
func (c *generalConfig) SecureCookies() bool {
	return c.viper.GetBool(EnvVarName("SecureCookies"))
}

// SessionTimeout is the maximum duration that a user session can persist without any activity.
func (c *generalConfig) SessionTimeout(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("SessionTimeout", ParseDuration, lggr).(time.Duration))
}

// StatsPusherLogging toggles very verbose logging of raw messages for the StatsPusher (also telemetry)
func (c *generalConfig) StatsPusherLogging(lggr logger.L) bool {
	return c.getWithFallback("StatsPusherLogging", ParseBool, lggr).(bool)
}

// TLSCertPath represents the file system location of the TLS certificate
// Chainlink should use for HTTPS.
func (c *generalConfig) TLSCertPath() string {
	return c.viper.GetString(EnvVarName("TLSCertPath"))
}

// TLSHost represents the hostname to use for TLS clients. This should match
// the TLS certificate.
func (c *generalConfig) TLSHost() string {
	return c.viper.GetString(EnvVarName("TLSHost"))
}

// TLSKeyPath represents the file system location of the TLS key Chainlink
// should use for HTTPS.
func (c *generalConfig) TLSKeyPath() string {
	return c.viper.GetString(EnvVarName("TLSKeyPath"))
}

// TLSPort represents the port Chainlink should listen on for encrypted client requests.
func (c *generalConfig) TLSPort(lggr logger.L) uint16 {
	return c.getWithFallback("TLSPort", ParseUint16, lggr).(uint16)
}

// TLSRedirect forces TLS redirect for unencrypted connections
func (c *generalConfig) TLSRedirect() bool {
	return c.viper.GetBool(EnvVarName("TLSRedirect"))
}

// UnAuthenticatedRateLimit defines the threshold to which requests unauthenticated requests get limited
func (c *generalConfig) UnAuthenticatedRateLimit() int64 {
	return c.viper.GetInt64(EnvVarName("UnAuthenticatedRateLimit"))
}

// UnAuthenticatedRateLimitPeriod defines the period to which unauthenticated requests get limited
func (c *generalConfig) UnAuthenticatedRateLimitPeriod(lggr logger.L) models.Duration {
	return models.MustMakeDuration(c.getWithFallback("UnAuthenticatedRateLimitPeriod", ParseDuration, lggr).(time.Duration))
}

func (c *generalConfig) TLSDir(lggr logger.L) string {
	return filepath.Join(c.RootDir(lggr), "tls")
}

// KeyFile returns the path where the server key is kept
func (c *generalConfig) KeyFile(lggr logger.L) string {
	if c.TLSKeyPath() == "" {
		return filepath.Join(c.TLSDir(lggr), "server.key")
	}
	return c.TLSKeyPath()
}

// CertFile returns the path where the server certificate is kept
func (c *generalConfig) CertFile(lggr logger.L) string {
	if c.TLSCertPath() == "" {
		return filepath.Join(c.TLSDir(lggr), "server.crt")
	}
	return c.TLSCertPath()
}

// SessionSecret returns a sequence of bytes to be used as a private key for
// session signing or encryption.
func (c *generalConfig) SessionSecret(lggr logger.L) ([]byte, error) {
	return c.secretGenerator.Generate(c.RootDir(lggr))
}

// SessionOptions returns the sessions.Options struct used to configure
// the session store.
func (c *generalConfig) SessionOptions() sessions.Options {
	return sessions.Options{
		Secure:   c.SecureCookies(),
		HttpOnly: true,
		MaxAge:   86400 * 30,
	}
}

// getWithFallback looks up the env var for name, falling back to the default or zero value if unset.
// Invalid user values are reported to lggr if provided.
func (c *generalConfig) getWithFallback(name string, parser func(string) (interface{}, error), lggr logger.L) interface{} {
	str := c.viper.GetString(EnvVarName(name))
	defaultValue, hasDefault := defaultValue(name)
	if str != "" {
		v, err := parser(str)
		if err == nil {
			return v
		}
		if lggr != nil {
			if hasDefault {
				lggr.Errorw(
					fmt.Sprintf("Invalid value provided for %s, falling back to default.", name),
					"value", str,
					"default", defaultValue,
					"error", err)
			} else {
				lggr.Errorw(
					fmt.Sprintf("Invalid value provided for %s, falling back to zero value.", name),
					"value", str,
					"error", err)
			}
		}
	}

	if !hasDefault {
		return zeroValue(name)
	}

	v, err := parser(defaultValue)
	if err != nil {
		log.Fatalf(`Invalid default for %s: "%s" (%s)`, name, defaultValue, err)
	}
	return v
}

// LogLevel determines the verbosity of the events to be logged.
type LogLevel struct {
	zapcore.Level
}

type DatabaseBackupMode string

var (
	DatabaseBackupModeNone DatabaseBackupMode = "none"
	DatabaseBackupModeLite DatabaseBackupMode = "lite"
	DatabaseBackupModeFull DatabaseBackupMode = "full"
)

func parseDatabaseBackupMode(s string) (interface{}, error) {
	switch DatabaseBackupMode(s) {
	case DatabaseBackupModeNone, DatabaseBackupModeLite, DatabaseBackupModeFull:
		return DatabaseBackupMode(s), nil
	default:
		return "", fmt.Errorf("unable to parse %v into DatabaseBackupMode. Must be one of values: \"%s\", \"%s\", \"%s\"", s, DatabaseBackupModeNone, DatabaseBackupModeLite, DatabaseBackupModeFull)
	}
}

// lookupEnv gets and parses the env var k if set.
// Invalid values are reported on lggr if provided.
func lookupEnv(k string, parse func(string) (interface{}, error), lggr logger.L) (interface{}, bool) {
	s, ok := os.LookupEnv(k)
	if ok {
		val, err := parse(s)
		if err != nil {
			if lggr != nil {
				lggr.Errorw(
					fmt.Sprintf("Invalid value provided for %s.", s),
					"value", s,
					"key", k,
					"error", err)
			}
			return nil, false
		}
		return val, true
	}
	return nil, false
}

// EVM methods

func (*generalConfig) GlobalBalanceMonitorEnabled(lggr logger.L) (bool, bool) {
	val, ok := lookupEnv(EnvVarName("BalanceMonitorEnabled"), ParseBool, lggr)
	if val == nil {
		return false, false
	}
	return val.(bool), ok
}
func (*generalConfig) GlobalBlockEmissionIdleWarningThreshold(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("BlockEmissionIdleWarningThreshold"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}
func (*generalConfig) GlobalBlockHistoryEstimatorBatchSize(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("BlockHistoryEstimatorBatchSize"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalBlockHistoryEstimatorBlockDelay(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("BlockHistoryEstimatorBlockDelay"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}
func (*generalConfig) GlobalBlockHistoryEstimatorBlockHistorySize(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("BlockHistoryEstimatorBlockHistorySize"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}
func (*generalConfig) GlobalBlockHistoryEstimatorTransactionPercentile(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("BlockHistoryEstimatorTransactionPercentile"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}
func (*generalConfig) GlobalEthTxReaperInterval(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("EthTxReaperInterval"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}
func (*generalConfig) GlobalEthTxReaperThreshold(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("EthTxReaperThreshold"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}
func (*generalConfig) GlobalEthTxResendAfterThreshold(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("EthTxResendAfterThreshold"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}
func (*generalConfig) GlobalEvmDefaultBatchSize(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmDefaultBatchSize"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalEvmFinalityDepth(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmFinalityDepth"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalEvmGasBumpPercent(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasBumpPercent"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}
func (*generalConfig) GlobalEvmGasBumpThreshold(lggr logger.L) (uint64, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasBumpThreshold"), ParseUint64, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint64), ok
}
func (*generalConfig) GlobalEvmGasBumpTxDepth(lggr logger.L) (uint16, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasBumpTxDepth"), ParseUint16, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint16), ok
}
func (*generalConfig) GlobalEvmGasBumpWei(lggr logger.L) (*big.Int, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasBumpWei"), ParseBigInt, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*big.Int), ok
}
func (*generalConfig) GlobalEvmGasLimitDefault(lggr logger.L) (uint64, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasLimitDefault"), ParseUint64, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint64), ok
}
func (*generalConfig) GlobalEvmGasLimitMultiplier(lggr logger.L) (float32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasLimitMultiplier"), ParseF32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(float32), ok
}
func (*generalConfig) GlobalEvmGasLimitTransfer(lggr logger.L) (uint64, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasLimitTransfer"), ParseUint64, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint64), ok
}
func (*generalConfig) GlobalEvmGasPriceDefault(lggr logger.L) (*big.Int, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasPriceDefault"), ParseBigInt, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*big.Int), ok
}
func (*generalConfig) GlobalEvmHeadTrackerHistoryDepth(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmHeadTrackerHistoryDepth"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalEvmHeadTrackerMaxBufferSize(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmHeadTrackerMaxBufferSize"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalEvmHeadTrackerSamplingInterval(lggr logger.L) (time.Duration, bool) {
	val, ok := lookupEnv(EnvVarName("EvmHeadTrackerSamplingInterval"), ParseDuration, lggr)
	if val == nil {
		return 0, false
	}
	return val.(time.Duration), ok
}
func (*generalConfig) GlobalEvmLogBackfillBatchSize(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmLogBackfillBatchSize"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalEvmMaxGasPriceWei(lggr logger.L) (*big.Int, bool) {
	val, ok := lookupEnv(EnvVarName("EvmMaxGasPriceWei"), ParseBigInt, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*big.Int), ok
}
func (*generalConfig) GlobalEvmMaxInFlightTransactions(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmMaxInFlightTransactions"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalEvmMaxQueuedTransactions(lggr logger.L) (uint64, bool) {
	val, ok := lookupEnv(EnvVarName("EvmMaxQueuedTransactions"), ParseUint64, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint64), ok
}
func (*generalConfig) GlobalEvmMinGasPriceWei(lggr logger.L) (*big.Int, bool) {
	val, ok := lookupEnv(EnvVarName("EvmMinGasPriceWei"), ParseBigInt, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*big.Int), ok
}
func (*generalConfig) GlobalEvmNonceAutoSync(lggr logger.L) (bool, bool) {
	val, ok := lookupEnv(EnvVarName("EvmNonceAutoSync"), ParseBool, lggr)
	if val == nil {
		return false, false
	}
	return val.(bool), ok
}
func (*generalConfig) GlobalEvmRPCDefaultBatchSize(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("EvmRPCDefaultBatchSize"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalFlagsContractAddress() (string, bool) {
	val, ok := lookupEnv(EnvVarName("FlagsContractAddress"), ParseString, nil)
	if val == nil {
		return "", false
	}
	return val.(string), ok
}
func (*generalConfig) GlobalGasEstimatorMode() (string, bool) {
	val, ok := lookupEnv(EnvVarName("GasEstimatorMode"), ParseString, nil)
	if val == nil {
		return "", false
	}
	return val.(string), ok
}
func (*generalConfig) GlobalChainType() (string, bool) {
	val, ok := lookupEnv(EnvVarName("ChainType"), ParseString, nil)
	if val == nil {
		return "", false
	}
	return val.(string), ok
}
func (*generalConfig) GlobalLinkContractAddress() (string, bool) {
	val, ok := lookupEnv(EnvVarName("LinkContractAddress"), ParseString, nil)
	if val == nil {
		return "", false
	}
	return val.(string), ok
}
func (*generalConfig) GlobalMinIncomingConfirmations(lggr logger.L) (uint32, bool) {
	val, ok := lookupEnv(EnvVarName("MinIncomingConfirmations"), ParseUint32, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint32), ok
}
func (*generalConfig) GlobalMinRequiredOutgoingConfirmations(lggr logger.L) (uint64, bool) {
	val, ok := lookupEnv(EnvVarName("MinRequiredOutgoingConfirmations"), ParseUint64, lggr)
	if val == nil {
		return 0, false
	}
	return val.(uint64), ok
}
func (*generalConfig) GlobalMinimumContractPayment(lggr logger.L) (*assets.Link, bool) {
	val, ok := lookupEnv(EnvVarName("MinimumContractPayment"), ParseLink, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*assets.Link), ok
}
func (*generalConfig) GlobalEvmEIP1559DynamicFees(lggr logger.L) (bool, bool) {
	val, ok := lookupEnv(EnvVarName("EvmEIP1559DynamicFees"), ParseBool, lggr)
	if val == nil {
		return false, false
	}
	return val.(bool), ok
}
func (*generalConfig) GlobalEvmGasTipCapDefault(lggr logger.L) (*big.Int, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasTipCapDefault"), ParseBigInt, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*big.Int), ok
}
func (*generalConfig) GlobalEvmGasTipCapMinimum(lggr logger.L) (*big.Int, bool) {
	val, ok := lookupEnv(EnvVarName("EvmGasTipCapMinimum"), ParseBigInt, lggr)
	if val == nil {
		return nil, false
	}
	return val.(*big.Int), ok
}

// UseLegacyEthEnvVars will upsert a new chain using the DefaultChainID and
// upsert nodes corresponding to the given ETH_URL and ETH_SECONDARY_URLS
func (c *generalConfig) UseLegacyEthEnvVars() bool {
	return c.viper.GetBool(EnvVarName("UseLegacyEthEnvVars"))
}

// DatabaseLockingMode can be one of 'dual', 'advisorylock', 'lease' or 'none'
// It controls which mode to use to enforce that only one Chainlink application can use the database
func (c *generalConfig) DatabaseLockingMode(lggr logger.L) string {
	return c.getWithFallback("DatabaseLockingMode", ParseString, lggr).(string)
}

// LeaseLockRefreshInterval controls how often the node should attempt to
// refresh the lease lock
func (c *generalConfig) LeaseLockRefreshInterval(lggr logger.L) time.Duration {
	return c.getDuration("LeaseLockRefreshInterval", lggr)
}

// LeaseLockDuration controls when the lock is set to expire on each refresh
// (this many seconds from now in the future)
func (c *generalConfig) LeaseLockDuration(lggr logger.L) time.Duration {
	return c.getDuration("LeaseLockDuration", lggr)
}

package keeper

import (
	"time"

	"github.com/smartcontractkit/chainlink/core/internal/gethwrappers/generated/keeper_registry_wrapper"
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/eth"
)

var RegistryABI = eth.MustGetABI(keeper_registry_wrapper.KeeperRegistryABI)

type Config interface {
	EvmEIP1559DynamicFees() bool
	KeeperDefaultTransactionQueueDepth() uint32
	KeeperGasPriceBufferPercent() uint32
	KeeperGasTipCapBufferPercent() uint32
	KeeperMaximumGracePeriod() int64
	KeeperRegistryCheckGasOverhead(logger.L) uint64
	KeeperRegistryPerformGasOverhead(logger.L) uint64
	KeeperRegistrySyncInterval(logger.L) time.Duration
	KeeperRegistrySyncUpkeepQueueSize(logger.L) uint32
	LogSQL() bool
}

package evm

import (
	"fmt"
	"math/big"
	"net/url"

	"github.com/pkg/errors"
	"gopkg.in/guregu/null.v4"

	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/utils"
	"github.com/smartcontractkit/sqlx"
)

type LegacyEthNodeConfig interface {
	DefaultChainID() (*big.Int, error)
	EthereumURL() string
	EthereumHTTPURL() (*url.URL, error)
	EthereumSecondaryURLs() ([]url.URL, error)
}

func ClobberDBFromEnv(db *sqlx.DB, config LegacyEthNodeConfig, lggr logger.Logger) error {
	var ethChainID *utils.Big
	if defaultChainID, err := config.DefaultChainID(); err != nil {
		return err
	} else {
		ethChainID = utils.NewBig(defaultChainID)
	}
	if ethChainID == nil {
		return errors.New("ETH_CHAIN_ID must be specified (or set USE_LEGACY_ETH_ENV_VARS=false)")
	}
	lggr.Infow(fmt.Sprintf("USE_LEGACY_ETH_ENV_VARS is on, upserting chain %s and replacing primary/send-only nodes. It is recommended "+
		"to set USE_LEGACY_ETH_ENV_VARS=false on subsequent runs and use the API to administer chains/nodes instead", ethChainID.String()),
		"evmChainID", ethChainID.String())

	if _, err := db.Exec("INSERT INTO evm_chains (id, created_at, updated_at) VALUES ($1, NOW(), NOW()) ON CONFLICT DO NOTHING;", ethChainID.String()); err != nil {
		return errors.Wrap(err, "failed to insert evm_chain")
	}

	if _, err := db.Exec("DELETE FROM nodes WHERE evm_chain_id = $1", ethChainID.String()); err != nil {
		return errors.Wrap(err, "failed to insert evm_chain")
	}

	stmt := `INSERT INTO nodes (name, evm_chain_id, ws_url, http_url, send_only, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,NOW(),NOW())`
	primaryWS := config.EthereumURL()
	if primaryWS == "" {
		return errors.New("ETH_URL must be specified (or set USE_LEGACY_ETH_ENV_VARS=false)")
	}
	var primaryHTTP null.String
	if pURL, err := config.EthereumHTTPURL(); err != nil {
		return err
	} else if pURL != nil {
		primaryHTTP = null.StringFrom(pURL.String())
	}
	if _, err := db.Exec(stmt, fmt.Sprintf("primary-0-%s", ethChainID), ethChainID, primaryWS, primaryHTTP, false); err != nil {
		return errors.Wrap(err, "failed to upsert primary-0")
	}

	eth2ndURLs, err := config.EthereumSecondaryURLs()
	if err != nil {
		return err
	}
	for i, url := range eth2ndURLs {
		name := fmt.Sprintf("sendonly-%d-%s", i, ethChainID)
		if _, err := db.Exec(stmt, name, ethChainID, nil, url.String(), true); err != nil {
			return errors.Wrapf(err, "failed to upsert %s", name)
		}
	}
	return nil

}

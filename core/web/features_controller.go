package web

import (
	"github.com/gin-gonic/gin"
	"github.com/smartcontractkit/chainlink/core/services/chainlink"
	"github.com/smartcontractkit/chainlink/core/web/presenters"
)

// FeaturesController manages the feature flags
type FeaturesController struct {
	App chainlink.Application
}

const (
	FeatureKeyCSA          string = "csa"
	FeatureKeyFeedsManager string = "feeds_manager"
)

// Index retrieves the features
// Example:
// "GET <application>/features"
func (fc *FeaturesController) Index(c *gin.Context) {
	cfg := fc.App.GetConfig()
	lggr := fc.App.GetLogger()
	resources := []presenters.FeatureResource{
		*presenters.NewFeatureResource(FeatureKeyCSA, cfg.FeatureUICSAKeys(lggr)),
		*presenters.NewFeatureResource(FeatureKeyFeedsManager, cfg.FeatureUIFeedsManager(lggr)),
	}

	jsonAPIResponse(c, resources, "features")
}

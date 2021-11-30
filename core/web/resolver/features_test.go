package resolver

import (
	"testing"

	"github.com/stretchr/testify/mock"
)

func Test_ToFeatures(t *testing.T) {
	query := `
	{
		features {
			... on Features {
				csa
				feedsManager
			}	
		}
	}`

	testCases := []GQLTestCase{
		unauthorizedTestCase(GQLTestCase{query: query}, "features"),
		{
			name:          "success",
			authenticated: true,
			before: func(f *gqlTestFramework) {
				f.App.On("GetConfig").Return(f.Mocks.cfg)
				f.Mocks.cfg.On("FeatureUICSAKeys", mock.Anything).Return(false)
				f.Mocks.cfg.On("FeatureUIFeedsManager", mock.Anything).Return(true)
			},
			query: query,
			result: `
			{
				"features": {
					"csa": false,
					"feedsManager": true
				}
			}`,
		},
	}

	RunGQLTests(t, testCases)
}

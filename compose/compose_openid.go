package compose

import (
	"github.com/ory/fosite/handler/openid"
)

func OpenIDConnectRefreshFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &openid.OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
	}
}

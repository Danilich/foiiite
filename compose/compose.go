package compose

import (
	"crypto/rsa"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type Factory func(config *Config, storage interface{}, strategy interface{}) interface{}

func Compose(config *Config, storage interface{}, strategy interface{}, hasher fosite.Hasher, factories ...Factory) fosite.OAuth2Provider {
	if hasher == nil {
		hasher = &fosite.BCrypt{WorkFactor: config.GetHashCost()}
	}

	f := &fosite.Fosite{
		Store:                        storage.(fosite.Storage),
		AuthorizeEndpointHandlers:    fosite.AuthorizeEndpointHandlers{},
		TokenEndpointHandlers:        fosite.TokenEndpointHandlers{},
		TokenIntrospectionHandlers:   fosite.TokenIntrospectionHandlers{},
		RevocationHandlers:           fosite.RevocationHandlers{},
		Hasher:                       hasher,
		ScopeStrategy:                config.GetScopeStrategy(),
		AudienceMatchingStrategy:     config.GetAudienceStrategy(),
		SendDebugMessagesToClients:   config.SendDebugMessagesToClients,
		TokenURL:                     config.TokenURL,
		JWKSFetcherStrategy:          config.GetJWKSFetcherStrategy(),
		MinParameterEntropy:          config.GetMinParameterEntropy(),
		UseLegacyErrorFormat:         config.UseLegacyErrorFormat,
		ClientAuthenticationStrategy: config.GetClientAuthenticationStrategy(),
		ResponseModeHandlerExtension: config.ResponseModeHandlerExtension,
		MessageCatalog:               config.MessageCatalog,
		FormPostHTMLTemplate:         config.FormPostHTMLTemplate,
	}

	for _, factory := range factories {
		res := factory(config, storage, strategy)
		if ah, ok := res.(fosite.AuthorizeEndpointHandler); ok {
			f.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(fosite.TokenEndpointHandler); ok {
			f.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(fosite.TokenIntrospector); ok {
			f.TokenIntrospectionHandlers.Append(tv)
		}
		if rh, ok := res.(fosite.RevocationHandler); ok {
			f.RevocationHandlers.Append(rh)
		}
	}

	return f
}

func ComposeAllEnabled(config *Config, storage interface{}, secret []byte, key *rsa.PrivateKey) fosite.OAuth2Provider {
	return Compose(
		config,
		storage,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config, secret, nil),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(config, key),
			JWTStrategy: &jwt.RS256JWTStrategy{
				PrivateKey: key,
			},
		},
		nil,

		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		OpenIDConnectRefreshFactory,
		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,
		OAuth2TokenExchangeFactory,
	)
}

package compose

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

type CommonStrategy struct {
	oauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.JWTStrategy
}

func NewOAuth2HMACStrategy(config *Config, secret []byte, rotatedSecrets [][]byte) *oauth2.HMACSHAStrategy {
	return &oauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			GlobalSecret:         secret,
			RotatedGlobalSecrets: rotatedSecrets,
			TokenEntropy:         config.GetTokenEntropy(),
		},
		AccessTokenLifespan:   config.GetAccessTokenLifespan(),
		AuthorizeCodeLifespan: config.GetAuthorizeCodeLifespan(),
		RefreshTokenLifespan:  config.GetRefreshTokenLifespan(),
	}
}

func NewOAuth2JWTStrategy(key *rsa.PrivateKey, strategy *oauth2.HMACSHAStrategy) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
		HMACSHAStrategy: strategy,
	}
}

func NewOAuth2JWTECDSAStrategy(key *ecdsa.PrivateKey, strategy *oauth2.HMACSHAStrategy) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		JWTStrategy: &jwt.ES256JWTStrategy{
			PrivateKey: key,
		},
		HMACSHAStrategy: strategy,
	}
}

// Deprecated: Use NewOAuth2JWTStrategy(key, strategy).WithIssuer(issuer) instead.
func NewOAuth2JWTStrategyWithIssuer(key *rsa.PrivateKey, strategy *oauth2.HMACSHAStrategy, issuer string) *oauth2.DefaultJWTStrategy {
	return NewOAuth2JWTStrategy(key, strategy).WithIssuer(issuer)
}

// Deprecated: Use NewOAuth2JWTECDSAStrategy(key, strategy).WithIssuer(issuer) instead.
func NewOAuth2JWTECDSAStrategyWithIssuer(key *ecdsa.PrivateKey, strategy *oauth2.HMACSHAStrategy, issuer string) *oauth2.DefaultJWTStrategy {
	return NewOAuth2JWTECDSAStrategy(key, strategy).WithIssuer(issuer)
}

func NewOpenIDConnectStrategy(config *Config, key *rsa.PrivateKey) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
		Expiry:              config.GetIDTokenLifespan(),
		Issuer:              config.IDTokenIssuer,
		MinParameterEntropy: config.GetMinParameterEntropy(),
	}
}

func NewOpenIDConnectECDSAStrategy(config *Config, key *ecdsa.PrivateKey) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		JWTStrategy: &jwt.ES256JWTStrategy{
			PrivateKey: key,
		},
		Expiry:              config.GetIDTokenLifespan(),
		Issuer:              config.IDTokenIssuer,
		MinParameterEntropy: config.GetMinParameterEntropy(),
	}
}

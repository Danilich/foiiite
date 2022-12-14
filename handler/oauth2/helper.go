package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
)

type HandleHelper struct {
	AccessTokenStrategy  AccessTokenStrategy
	AccessTokenStorage   AccessTokenStorage
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	token, signature, err := h.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return err
	} else if err := h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester.Sanitize([]string{})); err != nil {
		return err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(GetExpiresIn(requester, fosite.AccessToken, h.AccessTokenLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	return nil
}

func GetExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}

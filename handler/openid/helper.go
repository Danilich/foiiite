package openid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/ory/fosite"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

func (i *IDTokenHandleHelper) GetAccessTokenHash(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) string {
	token := responder.GetAccessToken()

	buffer := bytes.NewBufferString(token)
	hash := sha256.New()
	// sha256.digest.Write() always returns nil for err, the panic should never happen
	_, err := hash.Write(buffer.Bytes())
	if err != nil {
		panic(err)
	}
	hashBuf := bytes.NewBuffer(hash.Sum([]byte{}))

	return base64.RawURLEncoding.EncodeToString(hashBuf.Bytes()[:hashBuf.Len()/2])
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, fosr fosite.Requester) (token string, err error) {
	token, err = i.IDTokenStrategy.GenerateIDToken(ctx, fosr)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, ar fosite.Requester, resp fosite.AuthorizeResponder) error {
	token, err := i.generateIDToken(ctx, ar)
	if err != nil {
		return err
	}
	resp.AddParameter("id_token", token)
	return nil
}

func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, ar fosite.Requester, resp fosite.AccessResponder) error {
	token, err := i.generateIDToken(ctx, ar)
	if err != nil {
		return err
	}

	resp.SetExtra("id_token", token)
	return nil
}

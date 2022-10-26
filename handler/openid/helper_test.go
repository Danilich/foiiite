package openid

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
)

var strat = &DefaultStrategy{
	JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
	MinParameterEntropy: fosite.MinParameterEntropy,
}

var fooErr = errors.New("foo")

func TestGenerateIDToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	chgen := internal.NewMockOpenIDConnectTokenStrategy(ctrl)
	defer ctrl.Finish()

	ar := fosite.NewAccessRequest(nil)
	sess := &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "peter",
		},
		Headers: &jwt.Headers{},
	}
	h := &IDTokenHandleHelper{IDTokenStrategy: chgen}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because generator failed",
			setup: func() {
				ar.Form.Set("nonce", "11111111111111111111111111111111111")
				ar.SetSession(sess)
				chgen.EXPECT().GenerateIDToken(nil, ar).Return("", fooErr)
			},
			expectErr: fooErr,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().GenerateIDToken(nil, ar).AnyTimes().Return("asdf", nil)
			},
		},
	} {
		c.setup()
		token, err := h.generateIDToken(nil, ar)
		assert.True(t, err == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		if err == nil {
			assert.NotEmpty(t, token, "(%d) %s", k, c.description)
		}
		t.Logf("Passed test case %d", k)
	}

}

func TestGetAccessTokenHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := internal.NewMockAccessRequester(ctrl)
	resp := internal.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strat}

	hash := h.GetAccessTokenHash(nil, req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}

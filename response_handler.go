package fosite

import "net/http"

// ResponseModeHandler provides a contract for handling custom response modes
type ResponseModeHandler interface {
	// ResponseModes returns a set of supported response modes handled
	// by the interface implementation.
	//
	// In an authorize request with any of the provide response modes
	// methods `WriteAuthorizeResponse` and `WriteAuthorizeError` will be
	// invoked to write the successful or error authorization responses respectively.

	// WriteAuthorizeResponse writes successful responses
	//
	// Following headers are expected to be set by default:
	// header.Set("Cache-Control", "no-store")
	// header.Set("Pragma", "no-cache")
	WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder)

	// WriteAuthorizeError writes error responses
	//
	// Following headers are expected to be set by default:
	// header.Set("Cache-Control", "no-store")
	// header.Set("Pragma", "no-cache")
	WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error)
}

type DefaultResponseModeHandler struct{}

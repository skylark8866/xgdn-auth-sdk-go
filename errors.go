package authsdk

import "fmt"

// SDKError is a stable error for business branching.
type SDKError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message"`
	HTTP    int    `json:"http,omitempty"`
}

func (e *SDKError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != 0 {
		return fmt.Sprintf("code=%d message=%s", e.Code, e.Message)
	}
	if e.HTTP != 0 {
		return fmt.Sprintf("http %d: %s", e.HTTP, e.Message)
	}
	return e.Message
}

func newSDKError(msg string) *SDKError {
	return &SDKError{Message: msg}
}

func newHTTPError(status int, body string) *SDKError {
	return &SDKError{HTTP: status, Message: body}
}

func newAPIError(code int, message string) *SDKError {
	return &SDKError{Code: code, Message: message}
}

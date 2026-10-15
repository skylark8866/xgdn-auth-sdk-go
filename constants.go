package authsdk

const (
	DefaultBaseURL = "https://auth.xgdn.net"

	PathLoginSession   = "/api/v1/login/session"
	PathLoginQuery     = "/api/v1/login/query"
	PathSSESubscribe   = "/api/v1/sse/subscribe/{loginNo}"

	LoginStatusCreated   = "created"
	LoginStatusScanned   = "scanned"
	LoginStatusConfirmed = "confirmed"
	LoginStatusExpired   = "expired"
	LoginStatusRevoked   = "revoked"

	NotifyStatusOK = 1

	DefaultMaxDelaySec = 300
)

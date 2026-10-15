package sse

type EventName string

const (
	EventConnected   EventName = "connected"
	EventLoginNotify EventName = "login_notify"
	EventKeepAlive   EventName = "keep_alive"
)

func (e EventName) IsValid() bool {
	switch e {
	case EventConnected, EventLoginNotify, EventKeepAlive:
		return true
	default:
		return false
	}
}

const (
	SubscribePath            = "/api/v1/sse/subscribe/{loginNo}"
	DefaultSubscriberBaseURL = "https://auth.xgdn.net"
)

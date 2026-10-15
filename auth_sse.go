package authsdk

import (
	"github.com/skylark8866/xgdn-auth-sdk-go/sse"
)

// AuthSSE subscribes to gateway login_notify (no-site path).
type AuthSSE struct {
	subscriber *sse.Subscriber
	secret     string // optional; used by SubscribeVerified
}

type AuthSSEOption func(*authSSEConfig)

type authSSEConfig struct {
	baseURL string
	secret  string
	subOpts []sse.SubscriberOption
}

func WithSSEBaseURL(url string) AuthSSEOption {
	return func(c *authSSEConfig) {
		c.baseURL = url
	}
}

func WithSSESecret(secret string) AuthSSEOption {
	return func(c *authSSEConfig) {
		c.secret = secret
	}
}

func WithSSESubscriberOpts(opts ...sse.SubscriberOption) AuthSSEOption {
	return func(c *authSSEConfig) {
		c.subOpts = append(c.subOpts, opts...)
	}
}

func NewAuthSSE(opts ...AuthSSEOption) *AuthSSE {
	cfg := &authSSEConfig{baseURL: DefaultBaseURL}
	for _, opt := range opts {
		opt(cfg)
	}
	subOpts := append([]sse.SubscriberOption{}, cfg.subOpts...)
	if cfg.baseURL != "" {
		subOpts = append(subOpts, sse.WithBaseURL(cfg.baseURL))
	}
	return &AuthSSE{
		subscriber: sse.NewSubscriber(subOpts...),
		secret:     cfg.secret,
	}
}

// NewAuthSSEFromClient binds BaseURL + AppSecret from client.
func NewAuthSSEFromClient(c *Client, opts ...AuthSSEOption) *AuthSSE {
	all := []AuthSSEOption{WithSSEBaseURL(c.baseURL), WithSSESecret(c.appSecret)}
	all = append(all, opts...)
	return NewAuthSSE(all...)
}

func (a *AuthSSE) Subscribe(loginNo string, callback sse.LoginNotifyCallback) {
	a.subscriber.Subscribe(loginNo, callback)
}

// SubscribeVerified only invokes fn after flat-sign verify (requires secret via client or WithSSESecret).
func (a *AuthSSE) SubscribeVerified(loginNo string, fn func(*NotifyPayload) error) {
	secret := a.secret
	a.subscriber.Subscribe(loginNo, func(ev *sse.LoginNotifyEvent) {
		if !ev.IsConfirmed() || ev.Sign == "" {
			return
		}
		p := NotifyFromSSE(ev)
		if p == nil {
			return
		}
		if err := p.VerifyWithMaxDelay(secret, DefaultMaxDelaySec); err != nil {
			return
		}
		_ = fn(p)
	})
}

func (a *AuthSSE) Unsubscribe(loginNo string) {
	a.subscriber.Unsubscribe(loginNo)
}

func (a *AuthSSE) Shutdown() {
	a.subscriber.Close()
}

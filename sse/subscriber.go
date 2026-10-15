package sse

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LoginNotifyEvent is the SSE login_notify payload (signed fields + extras).
type LoginNotifyEvent struct {
	LoginStatus string `json:"login_status"`
	Status      any    `json:"status"`
	ReturnURL   string `json:"return_url,omitempty"`

	AppID       string `json:"app_id,omitempty"`
	LoginNo     string `json:"login_no,omitempty"`
	OutLoginNo  string `json:"out_login_no,omitempty"`
	OpenID      string `json:"openid,omitempty"`
	UserID      uint   `json:"user_id,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	Sign        string `json:"sign,omitempty"`
}

func (e *LoginNotifyEvent) IsConfirmed() bool {
	if e == nil {
		return false
	}
	if e.LoginStatus == "confirmed" {
		return true
	}
	if s, ok := e.Status.(string); ok && s == "confirmed" {
		return true
	}
	return false
}

func (e *LoginNotifyEvent) IsTerminal() bool {
	if e == nil {
		return false
	}
	st := e.LoginStatus
	if st == "" {
		if s, ok := e.Status.(string); ok {
			st = s
		}
	}
	return st == "confirmed" || st == "expired" || st == "revoked"
}

// NotifyLike is the signed subset shared with HTTP notify (avoid importing parent cycle).
type NotifyLike struct {
	AppID       string
	LoginNo     string
	OutLoginNo  string
	OpenID      string
	UserID      uint
	Nickname    string
	Avatar      string
	Status      int
	ConfirmedAt string
	Timestamp   string
	Nonce       string
	Sign        string
	LoginStatus string
	ReturnURL   string
}

func (e *LoginNotifyEvent) ToNotifyLike() *NotifyLike {
	if e == nil {
		return nil
	}
	return &NotifyLike{
		AppID: e.AppID, LoginNo: e.LoginNo, OutLoginNo: e.OutLoginNo,
		OpenID: e.OpenID, UserID: e.UserID, Nickname: e.Nickname, Avatar: e.Avatar,
		Status: statusInt(e.Status), ConfirmedAt: e.ConfirmedAt,
		Timestamp: e.Timestamp, Nonce: e.Nonce, Sign: e.Sign,
		LoginStatus: e.LoginStatus, ReturnURL: e.ReturnURL,
	}
}

func statusInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 1
	}
}

type LoginNotifyCallback func(event *LoginNotifyEvent)

type Logger interface {
	Printf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}

type Subscriber struct {
	baseURL       string
	httpClient    *http.Client
	logger        Logger
	reconnectMin  time.Duration
	reconnectMax  time.Duration
	mu            sync.Mutex
	subs          map[string]context.CancelFunc
	closed        bool
}

const (
	defaultReconnectDelay = 1 * time.Second
	maxReconnectDelay     = 60 * time.Second
)

var errStopSubscribe = errors.New("sse: stop subscribe")

type SubscriberOption func(*Subscriber)

func WithBaseURL(url string) SubscriberOption {
	return func(s *Subscriber) {
		s.baseURL = strings.TrimSuffix(url, "/")
	}
}

func WithLogger(l Logger) SubscriberOption {
	return func(s *Subscriber) {
		if l != nil {
			s.logger = l
		}
	}
}

func WithReconnect(min, max time.Duration) SubscriberOption {
	return func(s *Subscriber) {
		if min > 0 {
			s.reconnectMin = min
		}
		if max > 0 {
			s.reconnectMax = max
		}
	}
}

func NewSubscriber(opts ...SubscriberOption) *Subscriber {
	s := &Subscriber{
		httpClient:   &http.Client{Timeout: 0},
		logger:       nopLogger{},
		reconnectMin: defaultReconnectDelay,
		reconnectMax: maxReconnectDelay,
		subs:         make(map[string]context.CancelFunc),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.baseURL == "" {
		s.baseURL = DefaultSubscriberBaseURL
	}
	return s
}

func (s *Subscriber) Subscribe(loginNo string, callback LoginNotifyCallback) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.subs[loginNo]; exists {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.subs[loginNo] = cancel
	s.mu.Unlock()

	s.logger.Printf("[AuthSSE] subscribe %s", loginNo)
	go s.connectLoop(ctx, loginNo, callback)
}

func (s *Subscriber) Unsubscribe(loginNo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.subs[loginNo]; ok {
		cancel()
		delete(s.subs, loginNo)
	}
}

func (s *Subscriber) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for k, cancel := range s.subs {
		cancel()
		delete(s.subs, k)
	}
}

func (s *Subscriber) sseURL(loginNo string) string {
	return s.baseURL + strings.Replace(SubscribePath, "{loginNo}", loginNo, 1)
}

func (s *Subscriber) connectLoop(ctx context.Context, loginNo string, callback LoginNotifyCallback) {
	defer func() {
		s.mu.Lock()
		delete(s.subs, loginNo)
		s.mu.Unlock()
	}()

	delay := s.reconnectMin
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		connCtx, connCancel := context.WithCancel(ctx)
		err := s.connectAndRead(connCtx, loginNo, callback)
		connCancel()
		if errors.Is(err, errStopSubscribe) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < s.reconnectMax {
			delay *= 2
			if delay > s.reconnectMax {
				delay = s.reconnectMax
			}
		}
	}
}

func (s *Subscriber) connectAndRead(ctx context.Context, loginNo string, callback LoginNotifyCallback) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.sseURL(loginNo), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var eventName string
	var dataLines []string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		if line == "" {
			if EventName(eventName).IsValid() && len(dataLines) > 0 {
				data := strings.Join(dataLines, "")
				if eventName == string(EventLoginNotify) || eventName == string(EventConnected) {
					var event LoginNotifyEvent
					if err := json.Unmarshal([]byte(data), &event); err == nil {
						if event.LoginNo == "" {
							event.LoginNo = loginNo
						}
						callback(&event)
						if eventName == string(EventLoginNotify) && event.IsTerminal() {
							return errStopSubscribe
						}
					}
				}
			}
			eventName = ""
			dataLines = nil
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(line[5:]))
		}
	}
	return scanner.Err()
}

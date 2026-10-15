package authsdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	appID     string
	appSecret string
	baseURL   string
	http      *http.Client
}

type ClientOption func(*Client)

func WithAppConfig(appID, appSecret string) ClientOption {
	return func(c *Client) {
		if appID != "" {
			c.appID = appID
		}
		if appSecret != "" {
			c.appSecret = appSecret
		}
	}
}

func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		if httpClient != nil {
			c.http = httpClient
		}
	}
}

func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		if c.http == nil {
			c.http = &http.Client{}
		}
		c.http.Timeout = d
	}
}

// NewClient builds a client. Env: XGDN_AUTH_APP_ID / XGDN_AUTH_APP_SECRET / XGDN_AUTH_BASE_URL.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		appID:     os.Getenv("XGDN_AUTH_APP_ID"),
		appSecret: os.Getenv("XGDN_AUTH_APP_SECRET"),
		baseURL:   strings.TrimRight(envOr("XGDN_AUTH_BASE_URL", DefaultBaseURL), "/"),
		http:      &http.Client{Timeout: 15 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) AppID() string     { return c.appID }
func (c *Client) AppSecret() string { return c.appSecret }
func (c *Client) BaseURL() string   { return c.baseURL }

// SSE returns an AuthSSE bound to this client's BaseURL and AppSecret.
func (c *Client) SSE(opts ...AuthSSEOption) *AuthSSE {
	return NewAuthSSEFromClient(c, opts...)
}

func (c *Client) CreateLogin(ctx context.Context, in *CreateLoginRequest) (*CreateLoginResult, error) {
	var out CreateLoginResult
	if err := c.postSigned(ctx, PathLoginSession, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) QueryLogin(ctx context.Context, in *QueryLoginRequest) (*QueryLoginResult, error) {
	var out QueryLoginResult
	if err := c.postSigned(ctx, PathLoginQuery, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WaitForLogin polls Query until confirmed / terminal / timeout.
// Prefer AuthSSE for the main path; use this for reconnect / reconciliation only.
func (c *Client) WaitForLogin(ctx context.Context, loginNo string, interval, timeout time.Duration) (*QueryLoginResult, error) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q, err := c.QueryLogin(ctx, &QueryLoginRequest{LoginNo: loginNo})
		if err != nil {
			return nil, err
		}
		switch q.Status {
		case LoginStatusConfirmed:
			return q, nil
		case LoginStatusExpired, LoginStatusRevoked:
			return q, newSDKError("login ended: " + q.Status)
		}
		if time.Now().After(deadline) {
			return q, newSDKError("wait login timeout")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (c *Client) VerifyNotify(p *NotifyPayload) error {
	return p.VerifyWithMaxDelay(c.appSecret, DefaultMaxDelaySec)
}

func (c *Client) NotifyHandler(fn func(*NotifyPayload) error) http.HandlerFunc {
	return NotifyHandler(c.appSecret, fn)
}

type signedEnvelope struct {
	AppID     string          `json:"app_id"`
	Timestamp string          `json:"timestamp"`
	Nonce     string          `json:"nonce"`
	Data      json.RawMessage `json:"data"`
	Sign      string          `json:"sign"`
}

func (c *Client) postSigned(ctx context.Context, path string, data any, dest any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	compact, err := CompactSortedJSON(raw)
	if err != nil {
		return err
	}
	nonce, err := randomNonce(16)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body, err := json.Marshal(signedEnvelope{
		AppID:     c.appID,
		Timestamp: ts,
		Nonce:     nonce,
		Data:      raw,
		Sign:      SignV2(c.appID, compact, nonce, ts, c.appSecret),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return newHTTPError(resp.StatusCode, string(respBody))
	}
	var wrap struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(respBody, &wrap); err != nil {
		return err
	}
	if wrap.Error != "" {
		return newSDKError(wrap.Error)
	}
	if wrap.Code != 0 && len(wrap.Data) == 0 {
		return newAPIError(wrap.Code, wrap.Message)
	}
	if len(wrap.Data) == 0 {
		return json.Unmarshal(respBody, dest)
	}
	return json.Unmarshal(wrap.Data, dest)
}

func randomNonce(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

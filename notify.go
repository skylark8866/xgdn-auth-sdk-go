package authsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// NotifyPayload is the signed login-success webhook / SSE body.
type NotifyPayload struct {
	AppID       string `json:"app_id"`
	LoginNo     string `json:"login_no"`
	OutLoginNo  string `json:"out_login_no"`
	OpenID      string `json:"openid"`
	UserID      uint   `json:"user_id"`
	Nickname    string `json:"nickname"`
	Avatar      string `json:"avatar"`
	Status      int    `json:"status"`
	ConfirmedAt string `json:"confirmed_at"`
	Timestamp   string `json:"timestamp"`
	Nonce       string `json:"nonce"`
	Sign        string `json:"sign"`
	LoginStatus string `json:"login_status,omitempty"`
	ReturnURL   string `json:"return_url,omitempty"`
}

func ParseNotify(body []byte) (*NotifyPayload, error) {
	var p NotifyPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *NotifyPayload) flatParams() map[string]string {
	return map[string]string{
		"app_id":       p.AppID,
		"login_no":     p.LoginNo,
		"out_login_no": p.OutLoginNo,
		"openid":       p.OpenID,
		"user_id":      strconv.FormatUint(uint64(p.UserID), 10),
		"nickname":     p.Nickname,
		"avatar":       p.Avatar,
		"status":       strconv.Itoa(p.Status),
		"confirmed_at": p.ConfirmedAt,
		"timestamp":    p.Timestamp,
		"nonce":        p.Nonce,
	}
}

func (p *NotifyPayload) Verify(appSecret string) bool {
	return VerifyFlat(p.flatParams(), appSecret, p.Sign)
}

func (p *NotifyPayload) VerifyWithMaxDelay(appSecret string, maxDelaySec int64) error {
	if !p.Verify(appSecret) {
		return newSDKError("invalid sign")
	}
	if maxDelaySec <= 0 {
		maxDelaySec = DefaultMaxDelaySec
	}
	ts, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil {
		return newSDKError("bad timestamp")
	}
	if ts > 1e12 {
		ts = ts / 1000
	}
	skew := time.Now().Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > maxDelaySec {
		return newSDKError("timestamp out of range")
	}
	return nil
}

// NotifyHandler verifies sign and calls fn; on success writes plain SUCCESS.
func NotifyHandler(appSecret string, fn func(*NotifyPayload) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		p, err := ParseNotify(body)
		if err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := p.VerifyWithMaxDelay(appSecret, DefaultMaxDelaySec); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if err := fn(p); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "SUCCESS")
	}
}

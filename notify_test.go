package authsdk

import (
	"strconv"
	"testing"
	"time"

	"github.com/skylark8866/xgdn-auth-sdk-go/sse"
)

func TestNotifySignRoundTrip(t *testing.T) {
	secret := "sk_test"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	flat := map[string]string{
		"app_id": "app_x", "login_no": "lg1", "out_login_no": "o1",
		"openid": "oid", "user_id": "9", "nickname": "n", "avatar": "a",
		"status": "1", "confirmed_at": "2026-01-01 00:00:00",
		"timestamp": ts, "nonce": "abc",
	}
	sig := FlatSign(flat, secret)
	p := &NotifyPayload{
		AppID: "app_x", LoginNo: "lg1", OutLoginNo: "o1",
		OpenID: "oid", UserID: 9, Nickname: "n", Avatar: "a",
		Status: 1, ConfirmedAt: "2026-01-01 00:00:00",
		Timestamp: ts, Nonce: "abc", Sign: sig,
	}
	if err := p.VerifyWithMaxDelay(secret, DefaultMaxDelaySec); err != nil {
		t.Fatal(err)
	}
	c := NewClient(WithAppConfig("app_x", secret))
	if err := c.VerifyNotify(p); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyFromSSE(t *testing.T) {
	ev := &sse.LoginNotifyEvent{
		LoginStatus: "confirmed",
		Status:      float64(1),
		AppID:       "app",
		LoginNo:     "lg",
		OpenID:      "oid",
		Sign:        "x",
	}
	p := NotifyFromSSE(ev)
	if p == nil || p.OpenID != "oid" || p.Status != 1 || !ev.IsTerminal() {
		t.Fatalf("%+v", p)
	}
}

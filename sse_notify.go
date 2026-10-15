package authsdk

import "github.com/skylark8866/xgdn-auth-sdk-go/sse"

// NotifyFromSSE maps an SSE event to NotifyPayload for Verify.
func NotifyFromSSE(ev *sse.LoginNotifyEvent) *NotifyPayload {
	if ev == nil {
		return nil
	}
	n := ev.ToNotifyLike()
	if n == nil {
		return nil
	}
	return &NotifyPayload{
		AppID: n.AppID, LoginNo: n.LoginNo, OutLoginNo: n.OutLoginNo,
		OpenID: n.OpenID, UserID: n.UserID, Nickname: n.Nickname, Avatar: n.Avatar,
		Status: n.Status, ConfirmedAt: n.ConfirmedAt,
		Timestamp: n.Timestamp, Nonce: n.Nonce, Sign: n.Sign,
		LoginStatus: n.LoginStatus, ReturnURL: n.ReturnURL,
	}
}

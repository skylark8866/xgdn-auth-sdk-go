package authsdk

type CreateLoginRequest struct {
	OutLoginNo string         `json:"out_login_no,omitempty"`
	ReturnURL  string         `json:"return_url,omitempty"`
	NotifyURL  string         `json:"notify_url,omitempty"`
	Extra      map[string]any `json:"extra,omitempty"`
}

type CreateLoginResult struct {
	LoginNo   string `json:"login_no"`
	ScanURL   string `json:"scan_url"`             // 二维码内容：业务本地生成 PNG/SVG，勿拉中台 /qr.png
	LoginURL  string `json:"login_url,omitempty"`  // 仅调试；正式接入勿把浏览器导向中台
	ExpiresIn int    `json:"expires_in"`
}

type QueryLoginRequest struct {
	LoginNo    string `json:"login_no,omitempty"`
	OutLoginNo string `json:"out_login_no,omitempty"`
}

type QueryLoginResult struct {
	LoginNo     string `json:"login_no"`
	OutLoginNo  string `json:"out_login_no"`
	Status      string `json:"status"`
	OpenID      string `json:"openid,omitempty"`
	UserID      uint   `json:"user_id,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	ReturnURL   string `json:"return_url,omitempty"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

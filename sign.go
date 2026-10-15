package authsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func CompactSortedJSON(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "null", nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("invalid data json: %w", err)
	}
	sorted := sortValue(v)
	out, err := json.Marshal(sorted)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func sortValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortValue(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sortValue(e)
		}
		return out
	default:
		return v
	}
}

func SignV2(appID, dataCompact, nonce, timestamp, appSecret string) string {
	plain := strings.Join([]string{
		"app_id=" + appID,
		"data=" + dataCompact,
		"nonce=" + nonce,
		"timestamp=" + timestamp,
		"app_secret=" + appSecret,
	}, "&")
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func FlatSign(params map[string]string, appSecret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := params[k]
		if v == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("%s=%s&", k, v))
	}
	b.WriteString("app_secret=" + appSecret)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func VerifyFlat(params map[string]string, appSecret, want string) bool {
	return strings.EqualFold(FlatSign(params, appSecret), want)
}

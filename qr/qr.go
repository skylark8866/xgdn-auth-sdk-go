package qr

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// EncodePNG renders scan_url as PNG. Business sites should serve this themselves;
// do not fetch auth /qr.png.
func EncodePNG(scanURL string, size int) ([]byte, error) {
	if scanURL == "" {
		return nil, fmt.Errorf("empty scan_url")
	}
	if size < 64 {
		size = 256
	}
	return qrcode.Encode(scanURL, qrcode.Medium, size)
}

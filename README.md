# xgdn-auth Go SDK

业务侧接入微信扫码登录中台的 Go 客户端：签名创建会话、本地出码、AuthSSE / HTTP Notify 验签。

仓库：https://github.com/skylark8866/xgdn-auth-sdk-go  

**开发手册：[`开发手册.md`](./开发手册.md)**

```bash
go get github.com/skylark8866/xgdn-auth-sdk-go@latest
```

```go
import (
	authsdk "github.com/skylark8866/xgdn-auth-sdk-go"
	"github.com/skylark8866/xgdn-auth-sdk-go/qr"
)
```

C++ 平行实现：https://github.com/skylark8866/xgdn-auth-sdk-cpp  

package main

import (
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{contextID: contextID}
}

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32
}

// OnHttpRequestHeaders is called when the request headers are received.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	headers, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogCritical("failed to get request headers")
		return types.ActionContinue
	}

	for _, h := range headers {
		if detectAttack(h[1]) {
			proxywasm.LogWarnf("WAF Blocked Request (Header): %s", h[0])
			proxywasm.SendHttpResponse(403, nil, []byte("Forbidden by WAF"), -1)
			return types.ActionPause
		}
	}

	return types.ActionContinue
}

// OnHttpRequestBody is called when the request body is received.
func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	if bodySize == 0 {
		return types.ActionContinue
	}

	body, err := proxywasm.GetHttpRequestBody(0, bodySize)
	if err != nil {
		proxywasm.LogCritical("failed to get request body")
		return types.ActionContinue
	}

	if detectAttack(string(body)) {
		proxywasm.LogWarn("WAF Blocked Request (Body)")
		proxywasm.SendHttpResponse(403, nil, []byte("Forbidden by WAF"), -1)
		return types.ActionPause
	}

	return types.ActionContinue
}

func detectAttack(input string) bool {
	suspicious := []string{"<script>", "union select", "etc/passwd", "../.."}
	upperInput := strings.ToLower(input)
	for _, s := range suspicious {
		if strings.Contains(upperInput, s) {
			return true
		}
	}
	return false
}

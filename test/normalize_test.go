package test

import (
    "testing"
    "github.com/samaasi/go-waf/pkg/utils"
)

func TestNormalizeString_URL_HTML_Unicode(t *testing.T) {
    in := "%2555nion%20%53ELECT&quot;alert(1)&quot;"
    out := utils.NormalizeString(in)
    if out == in {
        t.Fatalf("expected normalization to change input")
    }
    if got := utils.NormalizeString("UNION\u200B SELECT"); got != "UNION SELECT" {
        t.Fatalf("zero-width removal failed: %q", got)
    }
}

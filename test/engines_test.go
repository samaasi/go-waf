package test

import (
    "context"
    "net/url"
    "testing"
    "github.com/samaasi/go-waf/internal/analysis/engines"
    "github.com/samaasi/go-waf/internal/domain"
)

func TestRegexEngine_NormalizedMatch(t *testing.T) {
    re := engines.NewRegexEngineWithPath("./configs/rules/regex_rules.json")
    if err := re.LoadRules(); err != nil {
        t.Skip("regex rules not available: " + err.Error())
    }
    q := url.Values{}
    q.Add("q", "%2555nion%20select")
    req := &domain.WafRequest{Path: "/", QueryArgs: q}
    events := re.Evaluate(context.Background(), req, 1)
    if len(events) == 0 {
        t.Fatalf("expected regex match after normalization")
    }
}

func TestFastMatchEngine_NormalizedMatch(t *testing.T) {
    e, err := engines.NewFastMatchEngine("./configs/rules/keywords.json")
    if err != nil {
        t.Skip("keywords.json not available: " + err.Error())
    }
    q := url.Values{}
    q.Add("q", "%2555nion%20select")
    req := &domain.WafRequest{Path: "/", QueryArgs: q}
    events := e.Evaluate(context.Background(), req, 1)
    if len(events) == 0 {
        t.Fatalf("expected fast match events for normalized input")
    }
}

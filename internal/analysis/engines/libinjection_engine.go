package engines

import (
	"context"
	"fmt"
	"strings"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/samaasi/go-waf/pkg/utils"

	"github.com/corazawaf/libinjection-go"
)

// LibinjectionEngine uses semantic analysis to detect SQLi and XSS.
// It is significantly more accurate than regex for these specific attack classes.
type LibinjectionEngine struct {
	threshold domain.Severity
}

func NewLibinjectionEngine() *LibinjectionEngine {
	return &LibinjectionEngine{
		threshold: domain.SeverityHigh,
	}
}

func (e *LibinjectionEngine) ID() string                { return "libinjection-semantic" }
func (e *LibinjectionEngine) Name() string              { return "Libinjection Semantic Analyzer" }
func (e *LibinjectionEngine) Tags() []string            { return []string{"semantic", "sqli", "xss"} }
func (e *LibinjectionEngine) Severity() domain.Severity { return domain.SeverityHigh }

func (e *LibinjectionEngine) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	var events []*domain.SecurityEvent

	if phase == 1 {
		if matched, fingerprint := e.checkSQLi(req.Path); matched {
			events = append(events, e.createEvent("SQLI", "SQL Injection in Path", fingerprint))
		}
		if matched := e.checkXSS(req.Path); matched {
			events = append(events, e.createEvent("XSS", "XSS in Path", "xss_detected"))
		}

		query := req.QueryArgs.Encode()
		if query != "" {
			if matched, fingerprint := e.checkSQLi(query); matched {
				events = append(events, e.createEvent("SQLI", "SQL Injection in Query", fingerprint))
			}
			if matched := e.checkXSS(query); matched {
				events = append(events, e.createEvent("XSS", "XSS in Query", "xss_detected"))
			}
		}

		for _, h := range []string{"User-Agent", "Referer", "Cookie"} {
			val := req.Headers.Get(h)
			if val == "" {
				continue
			}
			if matched, fingerprint := e.checkSQLi(val); matched {
				events = append(events, e.createEvent("SQLI", fmt.Sprintf("SQL Injection in Header (%s)", h), fingerprint))
			}
			if matched := e.checkXSS(val); matched {
				events = append(events, e.createEvent("XSS", fmt.Sprintf("XSS in Header (%s)", h), "xss_detected"))
			}
		}
	} else if phase == 2 {
		// Body
		if len(req.Body) > 0 {
			if isJSONBody(req.Body) {
				values := utils.ExtractValuesOnly(req.Body)
				for _, v := range values {
					if matched, fingerprint := e.checkSQLi(v); matched {
						events = append(events, e.createEvent("SQLI", "SQL Injection in Body", fingerprint))
						break
					}
					if matched := e.checkXSS(v); matched {
						events = append(events, e.createEvent("XSS", "XSS in Body", "xss_detected"))
						break
					}
				}
			} else {
				bodyStr := string(req.Body)
				if matched, fingerprint := e.checkSQLi(bodyStr); matched {
					events = append(events, e.createEvent("SQLI", "SQL Injection in Body", fingerprint))
				}
				if matched := e.checkXSS(bodyStr); matched {
					events = append(events, e.createEvent("XSS", "XSS in Body", "xss_detected"))
				}
			}
		}
	}

	return events
}

func (e *LibinjectionEngine) checkSQLi(input string) (bool, string) {
	if len(input) < 3 {
		return false, ""
	}
	// Normalization is already fast, but we only do it if the string looks suspicious to save cycles
	// However, for libinjection, it handles some noise itself.
	// We'll use a light normalization.
	norm := utils.NormalizeString(input)
	return libinjection.IsSQLi(norm)
}

func (e *LibinjectionEngine) checkXSS(input string) bool {
	if len(input) < 3 || !strings.ContainsAny(input, "<>'\"") {
		return false
	}
	return libinjection.IsXSS(input)
}

func (e *LibinjectionEngine) createEvent(idSuffix, name, matchedData string) *domain.SecurityEvent {
	return &domain.SecurityEvent{
		RuleID:      "LIBINJ-" + idSuffix,
		RuleName:    name,
		Severity:    domain.SeverityHigh,
		Message:     "Semantic attack detected",
		MatchedData: matchedData,
	}
}

func (e *LibinjectionEngine) LoadRules() error { return nil }

func isJSONBody(b []byte) bool {
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

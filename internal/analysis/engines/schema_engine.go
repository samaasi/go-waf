package engines

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/samaasi/go-waf/internal/domain"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

type SchemaEngine struct {
	specPath string
	doc      *openapi3.T
	router   routers.Router
	mu       sync.RWMutex
	logger   domain.Logger
}

func NewSchemaEngine(specPath string, log domain.Logger) *SchemaEngine {
	return &SchemaEngine{
		specPath: specPath,
		logger:   log,
	}
}

func (e *SchemaEngine) LoadRules() error {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(e.specPath)
	if err != nil {
		return fmt.Errorf("failed to load openapi spec: %w", err)
	}

	if err := doc.Validate(loader.Context); err != nil {
		return fmt.Errorf("invalid openapi spec: %w", err)
	}

	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return fmt.Errorf("failed to create openapi router: %w", err)
	}

	e.mu.Lock()
	e.doc = doc
	e.router = router
	e.mu.Unlock()

	e.logger.Info("OpenAPI schema loaded", domain.String("path", e.specPath))
	return nil
}

func (e *SchemaEngine) Evaluate(req *domain.WafRequest) []*domain.SecurityEvent {
	e.mu.RLock()
	router := e.router
	e.mu.RUnlock()

	if router == nil {
		return nil
	}

	httpReq, err := http.NewRequest(req.Method, req.Path, bytes.NewReader(req.Body))
	if err != nil {
		return nil
	}
	httpReq.Header = req.Headers
	httpReq.URL.RawQuery = url.Values(req.QueryArgs).Encode()

	route, pathParams, err := router.FindRoute(httpReq)
	if err != nil {
		return []*domain.SecurityEvent{{
			ID:          "SCHEMA_404",
			RuleName:    "api_path_not_allowed",
			Severity:    domain.SeverityMedium,
			MatchedData: fmt.Sprintf("path %s not defined in schema", req.Path),
		}}
	}

	validationInput := &openapi3filter.RequestValidationInput{
		Request:    httpReq,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			MultiError: true,
		},
	}

	if len(req.Body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(req.Body))
	}

	if err := openapi3filter.ValidateRequest(context.Background(), validationInput); err != nil {
		return []*domain.SecurityEvent{{
			ID:          "SCHEMA_VALIDATION_FAIL",
			RuleName:    "api_schema_violation",
			Severity:    domain.SeverityHigh,
			MatchedData: err.Error(),
		}}
	}

	return nil
}

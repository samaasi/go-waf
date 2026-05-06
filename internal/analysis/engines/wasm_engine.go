package engines

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/samaasi/go-waf/internal/domain"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type WasmEngine struct {
	runtime wazero.Runtime
	code    wazero.CompiledModule
	ctx     context.Context
	logger  domain.Logger
	pool    sync.Pool
}

func NewWasmEngine(ctx context.Context, wasmPath string, log domain.Logger) (*WasmEngine, error) {
	r := wazero.NewRuntime(ctx)

	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, size uint32) {
		msg, _ := m.Memory().Read(ptr, size)
		log.Info("[WASM-PLUGIN]", domain.String("msg", string(msg)))
	}).Export("log_info").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, size uint32) {
		msg, _ := m.Memory().Read(ptr, size)
		log.Error("[WASM-PLUGIN]", domain.String("msg", string(msg)))
	}).Export("log_error").
		Instantiate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate host module: %w", err)
	}

	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read WASM plugin: %w", err)
	}

	code, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile WASM module: %w", err)
	}

	engine := &WasmEngine{
		runtime: r,
		code:    code,
		ctx:     ctx,
		logger:  log,
	}

	engine.pool = sync.Pool{
		New: func() interface{} {
			mod, err := r.InstantiateModule(ctx, code, wazero.NewModuleConfig().WithName(""))
			if err != nil {
				log.Error("WASM lazy-instantiation failed", domain.Any("error", err))
				return nil
			}
			return mod
		},
	}

	return engine, nil
}

func (e *WasmEngine) ID() string   { return "wasm-extensibility" }
func (e *WasmEngine) Name() string { return "WASM Plugin Engine" }

func (e *WasmEngine) GetRules() []domain.RuleMetadata {
	return []domain.RuleMetadata{
		{ID: "WASM-BINARY", Name: "WASM Binary Logic", Severity: domain.SeverityHigh, Enabled: true, EngineID: e.ID()},
	}
}

func (e *WasmEngine) ToggleRule(id string, enabled bool) bool {
	return false
}

// LoadRules is a no-op for WASM engine as the logic is encapsulated in the binary
func (e *WasmEngine) LoadRules() error { return nil }

func (e *WasmEngine) Evaluate(ctx context.Context, req *domain.WafRequest, phase int) []*domain.SecurityEvent {
	if phase > 2 {
		return nil
	}
	// Get a module from the pool
	val := e.pool.Get()
	if val == nil {
		return nil
	}
	mod := val.(api.Module)
	defer e.pool.Put(mod)

	// Prepare request data
	input := fmt.Sprintf("%s|%s|%s", req.Method, req.Path, string(req.Body))
	inputSize := uint32(len(input))

	// Get ABI functions
	malloc := mod.ExportedFunction("malloc")
	inspect := mod.ExportedFunction("inspect")
	if malloc == nil || inspect == nil {
		return nil
	}

	results, err := malloc.Call(e.ctx, uint64(inputSize))
	if err != nil {
		return nil
	}
	inputPtr := uint32(results[0])

	if !mod.Memory().Write(inputPtr, []byte(input)) {
		return nil
	}

	inspectResults, err := inspect.Call(e.ctx, uint64(inputPtr), uint64(inputSize))
	if err != nil {
		e.logger.Error("WASM execution failed", domain.Any("error", err))
		return nil
	}

	score := int32(inspectResults[0])
	if score > 0 {
		return []*domain.SecurityEvent{
			{
				RuleID:   "WASM-PLUGIN-MATCH",
				RuleName: "WASM Custom Rule",
				Severity: domain.Severity(score / 10),
				Message:  fmt.Sprintf("WASM plugin reported violation score: %d", score),
			},
		}
	}

	return nil
}

func (e *WasmEngine) Close() error {
	return e.runtime.Close(e.ctx)
}

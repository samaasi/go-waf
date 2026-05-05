package config

import (
    "errors"
    "fmt"
    "os"
    "strings"

    "github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Security  SecurityConfig  `mapstructure:"security"`
	Log       LogConfig       `mapstructure:"log"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	TLS       TLSConfig       `mapstructure:"tls"`
}

type TelemetryConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	OrganizationID string `mapstructure:"organization_id"`
	APIKey         string `mapstructure:"api_key"`
	CollectorURL   string `mapstructure:"collector_url"`
	BatchSize      int    `mapstructure:"batch_size"`
	FlushInterval  int    `mapstructure:"flush_interval_ms"`
}

type ServerConfig struct {
    Port           string   `mapstructure:"port"`
    Mode           string   `mapstructure:"mode"`
    ReadTimeout    int      `mapstructure:"read_timeout"`
    WriteTimeout   int      `mapstructure:"write_timeout"`
    IdleTimeout    int      `mapstructure:"idle_timeout"`
    MaxBodyMB      int      `mapstructure:"max_body_mb"`
    MaxHeaderBytes int      `mapstructure:"max_header_bytes"`
    TrustedProxies []string `mapstructure:"trusted_proxies"`
    AdminAPIKey    string   `mapstructure:"admin_api_key"`
    AdminAPIKeyFile string  `mapstructure:"admin_api_key_file"`
    EnableProxy    bool     `mapstructure:"enable_proxy"`
    ProxyTarget    string   `mapstructure:"proxy_target"`
}

type RedisConfig struct {
	Host       string `mapstructure:"host"`
	Port       int    `mapstructure:"port"`
	Password   string `mapstructure:"password"`
	PasswordFile string `mapstructure:"password_file"`
	DB         int    `mapstructure:"db"`
	TLSEnabled bool   `mapstructure:"tls_enabled"`
}

type SecurityConfig struct {
    BlockThreshold           int      `mapstructure:"block_threshold"`
    RateLimit                int      `mapstructure:"rate_limit"`
    RateLimitKeyStrategy     string   `mapstructure:"rate_limit_key_strategy"` // "per_ip" (default), "per_ip_path"
    EnableGeoIP              bool     `mapstructure:"enable_geoip"`
    EnableBotShield          bool     `mapstructure:"enable_bot_shield"`
    RateLimitWindowSeconds   int      `mapstructure:"rate_limit_window_seconds"`
    RateLimitFailOpen        bool     `mapstructure:"rate_limit_fail_open"`
    AllowCountries           []string `mapstructure:"allow_countries"`
    BlockCountries           []string `mapstructure:"block_countries"`
    EnableSchemaValidation   bool     `mapstructure:"enable_schema_validation"`
    OpenAPISchemaPath        string   `mapstructure:"openapi_schema_path"`
    MaxMindLicenseKey        string   `mapstructure:"maxmind_license_key"`
    MaxMindLicenseKeyFile    string   `mapstructure:"maxmind_license_key_file"`
    GeoIPUpdateIntervalHours int      `mapstructure:"geoip_update_interval_hours"`
    Dlp                      DlpConfig `mapstructure:"dlp"`
    IPAllowlist              []string `mapstructure:"ip_allowlist"`
    IPBlocklist              []string `mapstructure:"ip_blocklist"`
}

type DlpConfig struct {
    Enabled bool   `mapstructure:"enabled"`
    Action  string `mapstructure:"action"` // "block" or "mask"
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

type TLSConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
	MinVersion   string `mapstructure:"min_version"` // "1.2" or "1.3"
	ClientAuth   string `mapstructure:"client_auth"` // "none", "request", "require"
	ClientCAFile string `mapstructure:"client_ca_file"`
}

const defaultAdminKey = "secret-waf-key"

func LoadConfig(path string) (*Config, error) {
    viper.AddConfigPath(path)
    viper.AddConfigPath("configs")
    if dir := os.Getenv("WAF_CONFIG_DIR"); dir != "" {
        viper.AddConfigPath(dir)
    }
    viper.SetConfigName("app-config")
    viper.SetConfigType("yaml")

	viper.SetEnvPrefix("WAF")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

    viper.SetDefault("server.port", "8080")
    viper.SetDefault("server.mode", "debug")
    viper.SetDefault("server.read_timeout", 30)
    viper.SetDefault("server.write_timeout", 30)
    viper.SetDefault("server.idle_timeout", 120)
    viper.SetDefault("server.max_body_mb", 10)
    viper.SetDefault("server.max_header_bytes", 1<<20) // 1MB
    viper.SetDefault("server.trusted_proxies", []string{})
    viper.SetDefault("server.admin_api_key", defaultAdminKey)
    viper.SetDefault("server.enable_proxy", false)
    viper.SetDefault("server.proxy_target", "http://localhost:3000")

	viper.SetDefault("redis.host", "127.0.0.1")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.tls_enabled", false)

    viper.SetDefault("security.block_threshold", 50)
    viper.SetDefault("security.rate_limit", 100)
    viper.SetDefault("security.rate_limit_key_strategy", "per_ip")
    viper.SetDefault("security.enable_geoip", false)
    viper.SetDefault("security.enable_bot_shield", false)
    viper.SetDefault("security.rate_limit_window_seconds", 1)
    viper.SetDefault("security.rate_limit_fail_open", true)
    viper.SetDefault("security.allow_countries", []string{})
    viper.SetDefault("security.block_countries", []string{})
    viper.SetDefault("security.enable_schema_validation", false)
    viper.SetDefault("security.openapi_schema_path", "./configs/rules/openapi.yaml")
    viper.SetDefault("security.maxmind_license_key", "")
    viper.SetDefault("security.geoip_update_interval_hours", 24)
    viper.SetDefault("security.dlp.enabled", false)
    viper.SetDefault("security.dlp.action", "block")
    viper.SetDefault("security.ip_allowlist", []string{})
    viper.SetDefault("security.ip_blocklist", []string{})

	viper.SetDefault("log.level", "info")

	viper.SetDefault("telemetry.enabled", false)
	viper.SetDefault("telemetry.collector_url", "https://api.snapwaf.com/v1/ingest")
	viper.SetDefault("telemetry.batch_size", 100)
	viper.SetDefault("telemetry.flush_interval_ms", 5000)

	viper.SetDefault("tls.enabled", false)
	viper.SetDefault("tls.min_version", "1.2")
	viper.SetDefault("tls.client_auth", "none")

	if err := viper.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if !errors.As(err, &nf) {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	resolveSecretFiles(&cfg)

	return &cfg, nil
}

// Validate enforces security invariants that must hold before the server starts.
func (c *Config) Validate() error {
	if c.Server.Mode == "release" && c.Server.AdminAPIKey == defaultAdminKey {
		return fmt.Errorf("FATAL: default admin API key must be changed in release mode. Set WAF_SERVER_ADMIN_API_KEY or server.admin_api_key")
	}
	if c.Server.AdminAPIKey != defaultAdminKey && len(c.Server.AdminAPIKey) < 32 {
		return fmt.Errorf("admin API key must be at least 32 characters (got %d)", len(c.Server.AdminAPIKey))
	}
	if c.Security.BlockThreshold <= 0 {
		return fmt.Errorf("security.block_threshold must be positive (got %d)", c.Security.BlockThreshold)
	}
	if c.Security.RateLimit <= 0 {
		return fmt.Errorf("security.rate_limit must be positive (got %d)", c.Security.RateLimit)
	}
	if c.Security.RateLimitWindowSeconds < 1 || c.Security.RateLimitWindowSeconds > 3600 {
		return fmt.Errorf("security.rate_limit_window_seconds must be 1-3600 (got %d)", c.Security.RateLimitWindowSeconds)
	}
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.cert_file and tls.key_file are required when TLS is enabled")
		}
	}
	return nil
}

// resolveSecretFiles reads secrets from file paths (for K8s secret volume mounts).
func resolveSecretFiles(cfg *Config) {
	if cfg.Server.AdminAPIKeyFile != "" {
		if data, err := os.ReadFile(cfg.Server.AdminAPIKeyFile); err == nil {
			cfg.Server.AdminAPIKey = strings.TrimSpace(string(data))
		}
	}
	if cfg.Redis.PasswordFile != "" {
		if data, err := os.ReadFile(cfg.Redis.PasswordFile); err == nil {
			cfg.Redis.Password = strings.TrimSpace(string(data))
		}
	}
	if cfg.Security.MaxMindLicenseKeyFile != "" {
		if data, err := os.ReadFile(cfg.Security.MaxMindLicenseKeyFile); err == nil {
			cfg.Security.MaxMindLicenseKey = strings.TrimSpace(string(data))
		}
	}
}

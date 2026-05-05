package config

import (
    "errors"
    "os"
    "strings"

    "github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Security SecurityConfig `mapstructure:"security"`
	Log       LogConfig       `mapstructure:"log"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
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
    Port         string `mapstructure:"port"`
    Mode         string `mapstructure:"mode"`
    ReadTimeout  int    `mapstructure:"read_timeout"`
    WriteTimeout int    `mapstructure:"write_timeout"`
    MaxBodyMB    int    `mapstructure:"max_body_mb"`
    TrustedProxies []string `mapstructure:"trusted_proxies"`
    AdminAPIKey  string `mapstructure:"admin_api_key"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type SecurityConfig struct {
    BlockThreshold int  `mapstructure:"block_threshold"`
    RateLimit      int  `mapstructure:"rate_limit"`
    EnableGeoIP    bool `mapstructure:"enable_geoip"`
    RateLimitWindowSeconds int `mapstructure:"rate_limit_window_seconds"`
    RateLimitFailOpen bool `mapstructure:"rate_limit_fail_open"`
    AllowCountries []string `mapstructure:"allow_countries"`
    BlockCountries []string `mapstructure:"block_countries"`
    EnableSchemaValidation bool `mapstructure:"enable_schema_validation"`
    OpenAPISchemaPath      string `mapstructure:"openapi_schema_path"`
    MaxMindLicenseKey      string `mapstructure:"maxmind_license_key"`
    GeoIPUpdateIntervalHours int `mapstructure:"geoip_update_interval_hours"`
    Dlp DlpConfig `mapstructure:"dlp"`
}

type DlpConfig struct {
    Enabled bool   `mapstructure:"enabled"`
    Action  string `mapstructure:"action"` // "block" or "mask"
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (*Config, error) {
    viper.AddConfigPath(path)
    viper.AddConfigPath("configs")
    if dir := os.Getenv("WAF_CONFIG_DIR"); dir != "" {
        viper.AddConfigPath(dir)
    }
    viper.SetConfigName("app-config")
    viper.SetConfigType("yaml")

	// Allow Environment Variables to override config (e.g., WAF_REDIS_HOST)
	viper.SetEnvPrefix("WAF")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults for local/dev environments
    viper.SetDefault("server.port", "8080")
    viper.SetDefault("server.mode", "debug")
    viper.SetDefault("server.read_timeout", 30)
    viper.SetDefault("server.write_timeout", 30)
    viper.SetDefault("server.max_body_mb", 10)
    viper.SetDefault("server.trusted_proxies", []string{})
    viper.SetDefault("server.admin_api_key", "secret-waf-key")

	viper.SetDefault("redis.host", "127.0.0.1")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

    viper.SetDefault("security.block_threshold", 50)
    viper.SetDefault("security.rate_limit", 100)
    viper.SetDefault("security.enable_geoip", false)
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

	viper.SetDefault("log.level", "info")

	viper.SetDefault("telemetry.enabled", false)
	viper.SetDefault("telemetry.collector_url", "https://api.snapwaf.com/v1/ingest")
	viper.SetDefault("telemetry.batch_size", 100)
	viper.SetDefault("telemetry.flush_interval_ms", 5000)

	if err := viper.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if !errors.As(err, &nf) {
			return nil, err
		}
		// No config file found; continue with env + defaults
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

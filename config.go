package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// OutputConfig represents a single output socket configuration.
type OutputConfig struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	AllowedKeys []string `json:"allowed_keys,omitempty"` // List of allowed key fingerprints (SHA256). If empty, all keys are allowed.
}

// Config represents the application configuration.
type Config struct {
	InputPath string         `json:"input_path"`
	Outputs   []OutputConfig `json:"outputs"`
}

// DefaultConfigPath returns the default path for the config file.
func DefaultConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "ssh-proxy", "config.json"), nil
}

// LoadConfig loads the configuration from the specified path.
// If the file doesn't exist, it creates a default configuration.
func LoadConfig(path string) (*Config, error) {
	// Check if config file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create default config
		config := &Config{
			InputPath: os.Getenv("SSH_AUTH_SOCK"),
			Outputs:   []OutputConfig{},
		}
		if err := SaveConfig(path, config); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		return config, nil
	}

	// Read existing config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves the configuration to the specified path.
func SaveConfig(path string, config *Config) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal config to JSON with indentation
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write config file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

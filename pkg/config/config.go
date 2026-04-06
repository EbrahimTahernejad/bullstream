// Package config defines YAML configuration structs for BullStream client and server.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ClientConfig holds all client-side configuration.
type ClientConfig struct {
	ListenAddr           string `yaml:"listen_addr"`
	Username             string `yaml:"username"`
	Password             string `yaml:"password"`
	PSK                  string `yaml:"psk"`
	DstAddr              string `yaml:"dst_addr"`
	HealthcheckIntervalS int    `yaml:"healthcheck_interval_s"`
	CtrlKeepaliveS       int    `yaml:"ctrl_keepalive_s"`
	DialTimeoutS         int    `yaml:"dial_timeout_s"`

	Upstream   ClientUpstreamConfig   `yaml:"upstream"`
	Downstream ClientDownstreamConfig `yaml:"downstream"`
}

// ClientUpstreamConfig describes which upstream transport to use.
type ClientUpstreamConfig struct {
	Type     string       `yaml:"type"` // "tcp" or "vless"
	CtrlDest string       `yaml:"ctrl_dest"`
	DataDest string       `yaml:"data_dest"`
	VLESS    *VLESSConfig `yaml:"vless,omitempty"`
}

// VLESSConfig holds VLESS-specific proxy parameters.
type VLESSConfig struct {
	Proxy string `yaml:"proxy"`
	UUID  string `yaml:"uuid"`
	TLS   bool   `yaml:"tls"`
}

// ClientDownstreamConfig describes which downstream transport the client requests.
type ClientDownstreamConfig struct {
	Type     string                `yaml:"type"` // "udp_spoof"
	UDPSpoof *ClientUDPSpoofConfig `yaml:"udp_spoof,omitempty"`
}

// ClientUDPSpoofConfig holds udp_spoof downstream parameters for the client.
type ClientUDPSpoofConfig struct {
	ListenPort   int      `yaml:"listen_port"`
	PublicIP     string   `yaml:"public_ip"`
	SpoofSources []string `yaml:"spoof_sources"`
	SpoofSelect  string   `yaml:"spoof_select"` // "random" or "round-robin"
}

// ServerConfig holds all server-side configuration.
type ServerConfig struct {
	CtrlListen  string `yaml:"ctrl_listen"`
	DataListen  string `yaml:"data_listen"`
	PSK         string `yaml:"psk"`
	SessionMode string `yaml:"session_mode"` // "single" or "multi"
	DialTimeout int    `yaml:"dial_timeout_s"`

	// Session tuning — all sent to client in ACK.
	FECData              int `yaml:"fec_data"`
	FECParity            int `yaml:"fec_parity"`
	FECFlushMs           int `yaml:"fec_flush_ms"`
	ReorderWindow        int `yaml:"reorder_window"`
	ReorderTimeoutMs     int `yaml:"reorder_timeout_ms"`
	SessionWindowBytes   int `yaml:"session_window_bytes"`
	MaxSessionsPerClient int `yaml:"max_sessions_per_client"`
	SessionIdleTimeoutS  int `yaml:"session_idle_timeout_s"`

	Downstream ServerDownstreamConfig `yaml:"downstream"`
	Users      []UserEntry            `yaml:"users"`
}

// ServerDownstreamConfig holds server-side downstream transport configuration.
type ServerDownstreamConfig struct {
	UDPSpoof *ServerUDPSpoofConfig `yaml:"udp_spoof,omitempty"`
}

// ServerUDPSpoofConfig holds server-side rate-limiting config for udp_spoof.
type ServerUDPSpoofConfig struct {
	RateMbps    float64 `yaml:"rate_mbps"`
	BurstGroups int     `yaml:"burst_groups"`
}

// UserEntry is one entry in the server users list.
type UserEntry struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// LoadClientConfig reads and parses a YAML client configuration file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config %q: %w", path, err)
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse client config %q: %w", path, err)
	}
	return &cfg, nil
}

// LoadServerConfig reads and parses a YAML server configuration file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config %q: %w", path, err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse server config %q: %w", path, err)
	}
	return &cfg, nil
}

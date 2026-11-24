// Package api defines the JSON protocol spoken over the autoban unix
// socket and a small client used by autoban-ctl.
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Request is one control command.
type Request struct {
	Cmd  string   `json:"cmd"`
	Jail string   `json:"jail,omitempty"`
	Args []string `json:"args,omitempty"`
}

// Response is the server reply. Data is a JSON value.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// ServerStatus summarises the daemon.
type ServerStatus struct {
	Version    string   `json:"version"`
	PID        int      `json:"pid"`
	Uptime     int64    `json:"uptime"` // seconds
	Jails      []string `json:"jails"`
	JailCount  int      `json:"jailCount"`
	Socket     string   `json:"socket"`
	ConfigDirs []string `json:"configDirs,omitempty"`
}

// BanInfo is one banned host.
type BanInfo struct {
	IP       string    `json:"ip"`
	Start    time.Time `json:"start"`
	Until    time.Time `json:"until,omitempty"`
	Duration int64     `json:"duration"` // seconds, negative = permanent
	Failures int       `json:"failures"`
	Matches  []string  `json:"matches,omitempty"`
	BanCount int       `json:"banCount"`
	Restored bool      `json:"restored,omitempty"`
}

// FailureInfo is failure state for one host.
type FailureInfo struct {
	IP        string    `json:"ip"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// JailStatus is the detailed status of one jail.
type JailStatus struct {
	Name             string    `json:"name"`
	Filter           string    `json:"filter"`
	FilterMode       string    `json:"filterMode,omitempty"`
	Backend          string    `json:"backend"`
	Files            []string  `json:"files"`
	Actions          []string  `json:"actions"`
	Started          bool      `json:"started"`
	CurrentlyFailed  int       `json:"currentlyFailed"`
	TotalFailed      int64     `json:"totalFailed"`
	CurrentlyBanned  int       `json:"currentlyBanned"`
	TotalBanned      int64     `json:"totalBanned"`
	TotalUnbanned    int64     `json:"totalUnbanned"`
	BannedIPs        []string  `json:"bannedIPs"`
	Banned           []BanInfo `json:"banned"`
	MaxRetry         int       `json:"maxRetry"`
	FindTime         int64     `json:"findTime"`
	BanTime          int64     `json:"banTime"`
	UsedNS           string    `json:"usedns"`
	IgnoreIP         []string  `json:"ignoreip"`
	BanTimeIncrement bool      `json:"banTimeIncrement"`
	BanTimeFactor    float64   `json:"banTimeFactor"`
	BanTimeMax       int64     `json:"banTimeMax"`
	BanTimeRnd       int64     `json:"banTimeRnd"`
	MaxLines         int       `json:"maxLines"`
	IgnoreCommand    string    `json:"ignoreCommand,omitempty"`
	DatePattern      string    `json:"datePattern,omitempty"`
	FilterWarnings   []string  `json:"filterWarnings,omitempty"`
}

// Value is a generic single-string result.
type Value struct {
	Value string `json:"value"`
}

// Message is a generic simple result.
type Message struct {
	Message string `json:"message"`
}

// Pong is returned by the ping command.
type Pong struct {
	Pong bool `json:"pong"`
}

// Client talks to the daemon over its unix socket.
type Client struct {
	Socket  string
	Timeout time.Duration
}

// NewClient returns a client for socket.
func NewClient(socket string) *Client {
	return &Client{Socket: socket, Timeout: 30 * time.Second}
}

// Do sends req and unmarshals the response data into out when out is non-nil.
func (c *Client) Do(req Request, out any) error {
	if c.Socket == "" {
		return fmt.Errorf("no socket configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conn, err := net.DialTimeout("unix", c.Socket, timeout)
	if err != nil {
		return fmt.Errorf("connect %s: %w", c.Socket, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	var resp Response
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown server error"
		}
		return fmt.Errorf("%s", resp.Error)
	}
	if out == nil || len(resp.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.Data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

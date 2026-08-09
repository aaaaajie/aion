// aion-bridge exposes the embedded fscan SDK through a strict NDJSON control
// protocol. Stdout is protocol-only; diagnostics are written to stderr.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	sdk "github.com/shadow1ng/fscan/pkg/fscan"
)

const protocolVersion = "1"

type startCommand struct {
	Type            string  `json:"type"`
	ProtocolVersion string  `json:"protocol_version"`
	TaskID          string  `json:"task_id"`
	Targets         string  `json:"targets"`
	Ports           string  `json:"ports"`
	Ping            bool    `json:"ping"`
	PingTCP         bool    `json:"ping_tcp"`
	Concurrency     int     `json:"concurrency"`
	TimeoutSeconds  float64 `json:"timeout_seconds"`
	WebMark         bool    `json:"web_mark"`
}

type controlCommand struct {
	Type   string `json:"type"`
	TaskID string `json:"task_id"`
}

type emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (e *emitter) send(value any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(value)
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(bufio.NewReader(input))
	var start startCommand
	if err := decoder.Decode(&start); err != nil {
		return fmt.Errorf("bridge start command: %w", err)
	}
	out := &emitter{enc: json.NewEncoder(output)}
	if err := validateStart(start); err != nil {
		_ = out.send(map[string]any{"type": "error", "code": "invalid_start", "message": err.Error()})
		return err
	}
	ports, err := parsePorts(start.Ports)
	if err != nil {
		_ = out.send(map[string]any{"type": "error", "code": "invalid_ports", "message": err.Error()})
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var summaryMu sync.Mutex
	var summary sdk.ResultSummary
	config := buildSDKConfig(start, ports)
	config.OnProgress = func(progress sdk.ScanProgress) {
		_ = out.send(map[string]any{
			"type":            "progress",
			"tasks_total":     progress.TasksTotal,
			"tasks_completed": progress.TasksCompleted,
			"duration_ms":     progress.Duration.Milliseconds(),
			"packets":         progress.Packets,
			"tcp_packets":     progress.TCPPackets,
			"http_packets":    progress.HTTPPackets,
			"paused":          progress.Paused,
		})
	}

	scanner := sdk.NewScanner(config)
	controller, statsCh, scanErrCh := scanner.ScanEachWithController(
		ctx,
		func(result sdk.Result) error {
			summaryMu.Lock()
			summary.Add(result)
			summaryMu.Unlock()
			return out.send(map[string]any{"type": "result", "result": result})
		},
	)
	if err := out.send(map[string]any{
		"type":             "ready",
		"protocol_version": protocolVersion,
		"scanner_version":  common.GetVersion(),
		"task_id":          start.TaskID,
	}); err != nil {
		cancel()
		return err
	}

	var stopped atomic.Bool
	controlErrCh := make(chan error, 1)
	go readControls(decoder, out, controller, cancel, start.TaskID, &stopped, controlErrCh)

	var scanErr error
	select {
	case scanErr = <-scanErrCh:
	case controlErr := <-controlErrCh:
		if controlErr != nil {
			cancel()
			scanErr = <-scanErrCh
			if scanErr == nil {
				scanErr = controlErr
			}
		}
	}
	stats := <-statsCh
	summaryMu.Lock()
	finalSummary := summary
	summaryMu.Unlock()
	status := "completed"
	if stopped.Load() {
		status = "stopped"
	}
	if scanErr != nil && !(stopped.Load() && errors.Is(scanErr, context.Canceled)) {
		_ = out.send(map[string]any{"type": "error", "code": "scan_failed", "message": scanErr.Error()})
		return scanErr
	}
	return out.send(map[string]any{
		"type":    "finished",
		"status":  status,
		"summary": finalSummary,
		"stats": map[string]any{
			"tasks_total":        stats.TasksTotal,
			"tasks_completed":    stats.TasksCompleted,
			"duration_ms":        stats.Duration.Milliseconds(),
			"packets":            stats.Packets,
			"tcp_packets":        stats.TCPPackets,
			"http_packets":       stats.HTTPPackets,
			"resource_exhausted": stats.ResourceExhausted,
		},
	})
}

func buildSDKConfig(start startCommand, ports []int) sdk.Config {
	config := sdk.Config{
		Targets:            []sdk.Target{{Host: start.Targets, Ports: ports}},
		Ports:              ports,
		DisablePlugins:     !start.WebMark,
		AllowUnsafePlugins: false,
		Timeout:            durationSeconds(start.TimeoutSeconds, 3*time.Second),
		WebTimeout:         durationSeconds(start.TimeoutSeconds, 3*time.Second),
		Threads:            start.Concurrency,
		ModuleThreads:      start.Concurrency,
		// TCP-only liveness is represented by scanning the requested ports
		// directly instead of running the ICMP pre-filter.
		DisablePing:    !start.Ping || start.PingTCP,
		DisableBrute:   true,
		DisablePOCScan: true,
		TaskID:         start.TaskID,
		MaxRetries:     1,
	}
	if start.WebMark {
		config.Plugins = []string{"webtitle"}
	}
	return config
}

func readControls(
	decoder *json.Decoder,
	out *emitter,
	controller *sdk.ScanController,
	cancel context.CancelFunc,
	taskID string,
	stopped *atomic.Bool,
	errCh chan<- error,
) {
	for {
		var command controlCommand
		if err := decoder.Decode(&command); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			_ = out.send(map[string]any{"type": "error", "code": "protocol_error", "message": err.Error()})
			errCh <- err
			return
		}
		if command.TaskID != "" && command.TaskID != taskID {
			err := fmt.Errorf("control task_id does not match active task")
			_ = out.send(map[string]any{"type": "error", "code": "task_mismatch", "message": err.Error()})
			errCh <- err
			return
		}
		switch command.Type {
		case "pause":
			controller.Pause()
		case "resume":
			controller.Resume()
		case "stop":
			stopped.Store(true)
			cancel()
			return
		default:
			err := fmt.Errorf("unsupported control command %q", command.Type)
			_ = out.send(map[string]any{"type": "error", "code": "protocol_error", "message": err.Error()})
			errCh <- err
			return
		}
	}
}

func validateStart(start startCommand) error {
	if start.Type != "start" {
		return fmt.Errorf("first command must be start")
	}
	if start.ProtocolVersion != protocolVersion {
		return fmt.Errorf("unsupported protocol version %q", start.ProtocolVersion)
	}
	if strings.TrimSpace(start.TaskID) == "" {
		return fmt.Errorf("task_id is required")
	}
	if strings.TrimSpace(start.Targets) == "" {
		return fmt.Errorf("targets are required")
	}
	if start.Concurrency < 1 {
		return fmt.Errorf("concurrency must be positive")
	}
	return nil
}

func durationSeconds(value float64, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value * float64(time.Second))
}

func parsePorts(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if strings.EqualFold(value, "all") {
		value = "1-65535"
	}
	seen := make(map[int]struct{})
	ports := make([]int, 0)
	for _, raw := range strings.Split(value, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		start, end := 0, 0
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			var err error
			start, err = strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", token)
			}
			end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
		} else {
			port, err := strconv.Atoi(token)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", token)
			}
			start, end = port, port
		}
		if start < 1 || end > 65535 {
			return nil, fmt.Errorf("port outside 1-65535: %q", token)
		}
		for port := start; port <= end; port++ {
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	return ports, nil
}

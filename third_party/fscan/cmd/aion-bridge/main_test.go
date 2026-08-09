package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBuildSDKConfigUsesExactPluginSelection(t *testing.T) {
	base := startCommand{
		Type:            "start",
		ProtocolVersion: protocolVersion,
		TaskID:          "task-1",
		Targets:         "127.0.0.1",
		Ports:           "80",
		Concurrency:     8,
	}
	withoutWeb := buildSDKConfig(base, []int{80})
	if !withoutWeb.DisablePlugins || len(withoutWeb.Plugins) != 0 {
		t.Fatalf("web_mark=false must disable plugins: %+v", withoutWeb)
	}
	if !withoutWeb.DisableBrute || !withoutWeb.DisablePOCScan || withoutWeb.AllowUnsafePlugins {
		t.Fatalf("unsafe scan capability was enabled: %+v", withoutWeb)
	}
	base.WebMark = true
	withWeb := buildSDKConfig(base, []int{80})
	if withWeb.DisablePlugins || len(withWeb.Plugins) != 1 || withWeb.Plugins[0] != "webtitle" {
		t.Fatalf("web_mark=true must select only webtitle: %+v", withWeb)
	}
	base.Ping = true
	base.PingTCP = true
	if config := buildSDKConfig(base, []int{80}); !config.DisablePing {
		t.Fatal("ping_tcp must bypass the ICMP pre-filter")
	}
}

func TestInvalidStartProducesProtocolError(t *testing.T) {
	input := bytes.NewBufferString(`{"type":"start","protocol_version":"9"}` + "\n")
	var output bytes.Buffer
	if err := run(input, &output); err == nil {
		t.Fatal("expected invalid start error")
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["type"] != "error" || event["code"] != "invalid_start" {
		t.Fatalf("unexpected protocol event: %#v", event)
	}
}

func TestParsePortsHasNoArtificialRangeCap(t *testing.T) {
	ports, err := parsePorts("1-65535")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 65535 || ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("unexpected range expansion: %d", len(ports))
	}
}

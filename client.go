package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/yiitz/cflib/crypto/tls"
)

func main() {
	testECHRequest()
}

func testECHRequest() {
	echConfigsList, err := parseECHConfig("-----BEGIN ECH CONFIGS-----\n" +
		"AEX+DQBBwQAgACCxNC4qLF6HdMSPFoYBdXKvpGCIng36fpaJuqCuxgjBDAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=" +
		"\n-----END ECH CONFIGS-----")

	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("GET", "https://www.cloudflare.com/ips-v4", nil)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&tls.Dialer{Config: &tls.Config{
					ECHEnabled:       true,
					ClientECHConfigs: echConfigsList,
					MinVersion:       tls.VersionTLS13,
				}}).DialContext(ctx, network, addr)
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v %v %v\n\n", resp.Status, resp.Proto, resp.ContentLength)
	for name, val := range resp.Header {
		fmt.Printf("%v: %v\n", name, val)
	}
	fmt.Println()
	fmt.Printf("%v\n", string(out))
}

func parseECHConfig(ech string) ([]tls.ECHConfig, error) {

	block, rest := pem.Decode([]byte(ech))
	if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
		return nil, errors.New("failed to PEM-decode the ECH configs")
	}

	echConfigsList, err := tls.UnmarshalECHConfigs(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECH configs: %v", err)
	}

	return echConfigsList, nil
}

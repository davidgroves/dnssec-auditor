package harness

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	Base string
	HTTP *http.Client
}

func NewClient(base string) *Client {
	return &Client{Base: base, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) get(path string, v any) error {
	resp, err := c.HTTP.Get(c.Base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, b)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *Client) Get(path string, v any) error { return c.get(path, v) }

func (c *Client) Ready() error {
	var m map[string]any
	return c.get("/ready", &m)
}

func (c *Client) Zone(name string) (map[string]any, error) {
	var m map[string]any
	err := c.get("/v1/zones/"+name, &m)
	return m, err
}

func (c *Client) Findings(name string) ([]map[string]any, error) {
	var wrap struct {
		Findings []map[string]any `json:"findings"`
	}
	err := c.get("/v1/zones/"+name+"/findings", &wrap)
	return wrap.Findings, err
}

func (c *Client) Metrics() (string, error) {
	resp, err := c.HTTP.Get(c.Base + "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func (c *Client) Refresh(name string, full bool) error {
	q := ""
	if full {
		q = "?full=true"
	}
	resp, err := c.HTTP.Post(c.Base+"/v1/zones/"+name+"/refresh"+q, "application/json", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("refresh %s", resp.Status)
	}
	return nil
}

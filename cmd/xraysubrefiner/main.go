package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Subscription struct {
	Key string `yaml:"key"`
	URL string `yaml:"url"`
}

type LiteCfg struct {
	// Kept for compatibility with config structure; Lite always takes last N now.
	Strategy     string `yaml:"strategy"`
	MaxTotal     int    `yaml:"max_total"`
	PerHostLimit int    `yaml:"per_host_limit"`
	N            int    `yaml:"n"`
}

type Config struct {
	AllowedSchemes []string       `yaml:"allowed_schemes"`
	Lite           LiteCfg        `yaml:"lite"`
	Subscriptions  []Subscription `yaml:"subscriptions"`
}

var (
	rePossibleB64 = regexp.MustCompile(`^[A-Za-z0-9+/=\r\n]+$`)
	reCommentLine = regexp.MustCompile(`^\s*(#|//|;).*$`)
)

// must: fail fast on unexpected errors.
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config.yaml")
	outDir := flag.String("out", "export", "output directory")
	timeout := flag.Duration("timeout", 20*time.Second, "HTTP client timeout")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	must(err)

	client := &http.Client{Timeout: *timeout}

	// Allowed schemes set
	allowed := map[string]struct{}{}
	for _, s := range cfg.AllowedSchemes {
		allowed[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	if len(allowed) == 0 {
		for _, s := range []string{"vless", "vmess", "ss"} {
			allowed[s] = struct{}{}
		}
	}

	for _, sub := range cfg.Subscriptions {
		fmt.Printf("Processing %s (%s)\n", sub.Key, sub.URL)
		raw, err := fetch(client, sub.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "!! fetch error %s: %v\n", sub.URL, err)
			continue
		}

		decoded := tryDecodeIfBase64(raw)
		valid := parseAndFilterLines(decoded, allowed)

		normal := dedupe(valid)
		lite := buildLiteTail(normal, 100) // take last 100 preserving order

		keyDir := filepath.Join(*outDir, sanitizeFileName(sub.Key))
		if err := os.MkdirAll(keyDir, 0o755); err != nil {
			must(err)
		}

		// Write Base64-encoded outputs (no file extension)
		if err := writeBase64Sorted(filepath.Join(keyDir, "normal"), normal); err != nil {
			must(err)
		}
		if err := writeBase64NoSort(filepath.Join(keyDir, "lite"), lite); err != nil {
			must(err)
		}
	}
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	// Reasonable defaults
	if cfg.Lite.MaxTotal <= 0 {
		cfg.Lite.MaxTotal = 100
	}
	if cfg.Lite.N <= 0 {
		cfg.Lite.N = 100
	}
	return &cfg, nil
}

func fetch(client *http.Client, rawurl string) ([]byte, error) {
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "XraySubRefiner/1.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func tryDecodeIfBase64(b []byte) []byte {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 {
		return trim
	}
	if !rePossibleB64.Match(trim) {
		return b
	}
	dec, err := base64.StdEncoding.DecodeString(string(trim))
	if err != nil {
		dec2, err2 := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(trim), "\n", ""))
		if err2 != nil {
			return b
		}
		dec = dec2
	}
	l := strings.ToLower(string(dec))
	if strings.Contains(l, "vless://") || strings.Contains(l, "vmess://") || strings.Contains(l, "ss://") {
		return dec
	}
	return b
}

func parseAndFilterLines(b []byte, allowed map[string]struct{}) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	// Increase Scanner buffer for large lines
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || reCommentLine.MatchString(line) {
			continue
		}
		items := splitPossible(line)
		for _, it := range items {
			it = strings.TrimSpace(it)
			if it == "" || reCommentLine.MatchString(it) {
				continue
			}
			l := strings.ToLower(it)
			ok := false
			for sch := range allowed {
				if strings.HasPrefix(l, sch+"://") {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
			out = append(out, normalizeScheme(it))
		}
	}
	return out
}

func normalizeScheme(s string) string {
	idx := strings.Index(s, "://")
	if idx < 0 {
		return s
	}
	return strings.ToLower(s[:idx]) + s[idx:]
}

func splitPossible(s string) []string {
	if strings.Count(s, "://") <= 1 {
		return []string{s}
	}
	parts := []string{}
	cur := s
	for {
		idx := strings.Index(cur, "://")
		if idx < 0 {
			break
		}
		start := idx - 1
		for start >= 0 && isSchemeChar(cur[start]) {
			start--
		}
		start++
		rest := cur[start:]
		next := strings.Index(rest[3:], "://")
		if next >= 0 {
			parts = append(parts, strings.TrimSpace(rest[:next+3]))
			cur = rest[next+3:]
			continue
		}
		parts = append(parts, strings.TrimSpace(rest))
		break
	}
	return parts
}

func isSchemeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		k := strings.TrimSpace(s)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// buildLiteTail returns the last n items from normal, preserving order.
func buildLiteTail(normal []string, n int) []string {
	if n <= 0 {
		n = 100
	}
	if n > len(normal) {
		n = len(normal)
	}
	start := len(normal) - n
	return append([]string(nil), normal[start:]...)
}

// hostKey kept for potential future strategies; not used in tail selection.
func hostKey(line string) string {
	u, err := url.Parse(line)
	if err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	if at := strings.Index(line, "@"); at >= 0 {
		rest := line[at+1:]
		stop := len(rest)
		if i := strings.IndexAny(rest, "?#"); i >= 0 {
			stop = i
		}
		hostport := rest[:stop]
		return strings.ToLower(hostport)
	}
	return strings.ToLower(line)
}

// writeBase64Sorted writes lines sorted, as a single Base64-encoded payload.
func writeBase64Sorted(path string, lines []string) error {
	cp := append([]string(nil), lines...)
	sort.Strings(cp)
	return writeBase64Atomic(path, cp)
}

// writeBase64NoSort writes lines in the given order, as a single Base64-encoded payload.
func writeBase64NoSort(path string, lines []string) error {
	return writeBase64Atomic(path, lines)
}

// writeBase64Atomic joins lines with '\n', encodes the entire content in Base64,
// then writes atomically with retries (Windows-friendly).
func writeBase64Atomic(path string, lines []string) error {
	payload := strings.Join(lines, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmpFile, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	w := bufio.NewWriter(tmpFile)
	if _, err := w.WriteString(encoded); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := w.Flush(); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	const maxRetries = 6
	for i := 0; i < maxRetries; i++ {
		_ = os.Remove(path) // ignore error if not exists
		if err := os.Rename(tmpPath, path); err != nil {
			lower := strings.ToLower(err.Error())
			busy := strings.Contains(lower, "used by another process") ||
				strings.Contains(lower, "access is denied") ||
				strings.Contains(lower, "sharing violation")
			if busy && i < maxRetries-1 {
				time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
				continue
			}
			_ = os.Remove(tmpPath)
			return fmt.Errorf("rename failed (%d tries): %w", i+1, err)
		}
		return nil
	}
	_ = os.Remove(tmpPath)
	return fmt.Errorf("rename failed after retries")
}

func sanitizeFileName(name string) string {
	name = strings.TrimSpace(name)
	invalid := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	name = invalid.ReplaceAllString(name, "_")
	if name == "" {
		name = "default"
	}
	return name
}
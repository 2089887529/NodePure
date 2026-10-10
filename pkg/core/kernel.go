package core

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/2089887529/NodePure/pkg/config"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type KernelInstance struct {
	cmd      *exec.Cmd
	tempDir  string
	cancel   context.CancelFunc
	Done     chan struct{}
	waitErr  error
	once     sync.Once
	Nodes    []*ProxyNode
	Rejected []ParseWarning
	ports    []int
}
type boundedLog struct {
	mu   sync.Mutex
	data []byte
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if len(b.data) > 64<<10 {
		b.data = append([]byte(nil), b.data[len(b.data)-(64<<10):]...)
	}
	return len(p), nil
}
func (b *boundedLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

var downloadMu, portMu sync.Mutex
var allocated = map[int]bool{}

func FindOrDownloadMihomo(ctx context.Context) (string, error) {
	downloadMu.Lock()
	defer downloadMu.Unlock()
	path := config.Global.MihomoBin
	if runtime.GOOS == "windows" && path == "./bin/mihomo" {
		path += ".exe"
	}
	if st, e := os.Stat(path); e == nil && !st.IsDir() {
		return filepath.Abs(path)
	}
	if p, e := exec.LookPath("mihomo"); e == nil {
		return p, nil
	}
	if len(config.Global.MihomoSHA256) != 64 {
		return "", fmt.Errorf("Mihomo missing: install it at MIHOMO_BIN, or set a verified MIHOMO_SHA256 archive checksum for automatic download")
	}
	if e := downloadMihomo(ctx, path, config.Global.MihomoSHA256); e != nil {
		return "", e
	}
	return filepath.Abs(path)
}
func downloadMihomo(ctx context.Context, target, checksum string) error {
	if _, e := hex.DecodeString(checksum); e != nil {
		return fmt.Errorf("invalid Mihomo archive checksum")
	}
	ext := ".gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	asset := fmt.Sprintf("mihomo-%s-%s-v1.19.32%s", runtime.GOOS, runtime.GOARCH, ext)
	req, e := http.NewRequestWithContext(ctx, "GET", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/"+asset, nil)
	if e != nil {
		return e
	}
	client := &http.Client{Timeout: 90 * time.Second}
	resp, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("Mihomo download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Mihomo download HTTP %d", resp.StatusCode)
	}
	archive, e := io.ReadAll(io.LimitReader(resp.Body, (128<<20)+1))
	if e != nil || len(archive) > 128<<20 {
		return fmt.Errorf("Mihomo archive read/size error")
	}
	sum := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), checksum) {
		return fmt.Errorf("Mihomo archive checksum mismatch")
	}
	var reader io.ReadCloser
	if ext == ".gz" {
		reader, e = gzip.NewReader(bytes.NewReader(archive))
	} else {
		var z *zip.Reader
		z, e = zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if e == nil {
			for _, f := range z.File {
				if !f.FileInfo().IsDir() && strings.HasPrefix(filepath.Base(f.Name), "mihomo") && strings.HasSuffix(f.Name, ".exe") {
					reader, e = f.Open()
					break
				}
			}
		}
	}
	if e != nil || reader == nil {
		return fmt.Errorf("invalid Mihomo archive")
	}
	defer reader.Close()
	if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		return e
	}
	out, e := os.CreateTemp(filepath.Dir(target), ".mihomo-*")
	if e != nil {
		return e
	}
	name := out.Name()
	defer os.Remove(name)
	n, e := io.Copy(out, io.LimitReader(reader, (256<<20)+1))
	if e == nil && n > 256<<20 {
		e = fmt.Errorf("Mihomo decompression size exceeded")
	}
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Chmod(name, 0755); e != nil {
		return e
	}
	return os.Rename(name, target)
}
func reservePorts(count int) ([]net.Listener, []int, error) {
	portMu.Lock()
	defer portMu.Unlock()
	var listeners []net.Listener
	var ports []int
	for len(ports) < count {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			for _, x := range listeners {
				x.Close()
			}
			for _, p := range ports {
				delete(allocated, p)
			}
			return nil, nil, e
		}
		p := l.Addr().(*net.TCPAddr).Port
		if allocated[p] {
			l.Close()
			continue
		}
		allocated[p] = true
		ports = append(ports, p)
		listeners = append(listeners, l)
	}
	return listeners, ports, nil
}
func releasePorts(ports []int) {
	portMu.Lock()
	defer portMu.Unlock()
	for _, p := range ports {
		delete(allocated, p)
	}
}
func closeReservations(ls []net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}
func checkSOCKS(ctx context.Context, node *ProxyNode) error {
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	conn, e := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(node.LocalPort)))
	if e != nil {
		return e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, e = conn.Write([]byte{5, 1, 2}); e != nil {
		return e
	}
	reply := make([]byte, 2)
	if _, e = io.ReadFull(conn, reply); e != nil {
		return e
	}
	if reply[0] != 5 || reply[1] != 2 {
		return fmt.Errorf("unexpected SOCKS authentication")
	}
	auth := append([]byte{1, byte(len(node.ProxyUser))}, []byte(node.ProxyUser)...)
	auth = append(auth, byte(len(node.ProxyPassword)))
	auth = append(auth, []byte(node.ProxyPassword)...)
	if _, e = conn.Write(auth); e != nil {
		return e
	}
	if _, e = io.ReadFull(conn, reply); e != nil {
		return e
	}
	if reply[0] != 1 || reply[1] != 0 {
		return fmt.Errorf("SOCKS authentication rejected")
	}
	return nil
}

// Some Windows policies deny executable access to the system temporary directory.
// Keep each task isolated, and use the user's cache if the OS temp directory fails.
func makeKernelTemp() (string, error) {
	if root := config.Global.TempDir; root != "" {
		dir, e := os.MkdirTemp(root, "nodepure-")
		if e != nil {
			return "", fmt.Errorf("cannot create private kernel directory; NODEPURE_TEMP_DIR must be an existing writable private directory")
		}
		return dir, nil
	}
	if dir, e := os.MkdirTemp("", "nodepure-"); e == nil {
		return dir, nil
	}
	if cache, e := os.UserCacheDir(); e == nil {
		root := filepath.Join(cache, "NodePure", "tmp")
		if e = os.MkdirAll(root, 0700); e == nil {
			if dir, e := os.MkdirTemp(root, "nodepure-"); e == nil {
				return dir, nil
			}
		}
	}
	return "", fmt.Errorf("cannot create private kernel directory; set NODEPURE_TEMP_DIR to an existing writable private directory")
}
func StartKernelForNodes(ctx context.Context, nodes []*ProxyNode) (*KernelInstance, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes")
	}
	bin, e := FindOrDownloadMihomo(ctx)
	if e != nil {
		return nil, e
	}
	dir, e := makeKernelTemp()
	if e != nil {
		return nil, e
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(dir)
		}
	}()
	current := make([]*ProxyNode, len(nodes))
	for i, n := range nodes {
		copy := *n
		current[i] = &copy
	}
	var rejected []ParseWarning
	badPattern := regexp.MustCompile(`proxy (\d+):`)
	token := make([]byte, 16)
	if _, e = rand.Read(token); e != nil {
		return nil, e
	}
	user, password := "nodepure", hex.EncodeToString(token)
	for attempt := 0; attempt <= len(nodes); attempt++ {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if len(current) == 0 {
			return nil, fmt.Errorf("all nodes incompatible with Mihomo")
		}
		sockets, ports, e := reservePorts(len(current))
		if e != nil {
			return nil, fmt.Errorf("cannot reserve local probe ports")
		}
		var listeners, proxies []map[string]interface{}
		for i, n := range current {
			n.LocalPort = ports[i]
			n.ProxyUser = user
			n.ProxyPassword = password
			listeners = append(listeners, map[string]interface{}{"name": fmt.Sprintf("listener-%d", i), "type": "mixed", "listen": "127.0.0.1", "port": ports[i], "udp": false, "proxy": n.Name, "users": []map[string]string{{"username": user, "password": password}}})
			proxies = append(proxies, n.RawConfig)
		}
		cfg := map[string]interface{}{"mode": "rule", "log-level": "warning", "listeners": listeners, "proxies": proxies, "rules": []string{"MATCH,REJECT"}, "geodata-mode": false, "ipv6": true}
		b, e := yaml.Marshal(cfg)
		if e == nil {
			e = os.WriteFile(filepath.Join(dir, "config.yaml"), b, 0600)
		}
		if e != nil {
			closeReservations(sockets)
			releasePorts(ports)
			return nil, fmt.Errorf("cannot write kernel config")
		}
		validationCtx, cancelValidation := context.WithTimeout(ctx, 10*time.Second)
		log := &boundedLog{}
		test := exec.CommandContext(validationCtx, bin, "-d", dir, "-t")
		test.Stdout = log
		test.Stderr = log
		e = test.Run()
		cancelValidation()
		if e != nil {
			closeReservations(sockets)
			releasePorts(ports)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			match := badPattern.FindStringSubmatch(log.String())
			if len(match) == 2 {
				idx, _ := strconv.Atoi(match[1])
				if idx >= 0 && idx < len(current) {
					n := current[idx]
					rejected = append(rejected, ParseWarning{n.ID, n.Name, "Mihomo 配置校验不通过"})
					current = append(current[:idx], current[idx+1:]...)
					continue
				}
			}
			return nil, fmt.Errorf("Mihomo config validation failed; check protocol/version and node settings")
		}
		runCtx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(runCtx, bin, "-d", dir, "-f", filepath.Join(dir, "config.yaml"))
		cmd.Stdout = log
		cmd.Stderr = log
		closeReservations(sockets)
		if e = cmd.Start(); e != nil {
			cancel()
			releasePorts(ports)
			return nil, fmt.Errorf("cannot start Mihomo")
		}
		k := &KernelInstance{cmd: cmd, tempDir: dir, cancel: cancel, Done: make(chan struct{}), Nodes: current, Rejected: rejected, ports: ports}
		go func() { k.waitErr = cmd.Wait(); close(k.Done) }()
		readyCtx, cancelReady := context.WithTimeout(ctx, 5*time.Second)
		ready := false
		for readyCtx.Err() == nil {
			select {
			case <-k.Done:
				cancelReady()
				k.Stop()
				return nil, fmt.Errorf("Mihomo exited during startup")
			default:
			}
			ready = true
			for _, n := range current {
				if checkSOCKS(readyCtx, n) != nil {
					ready = false
					break
				}
			}
			if ready {
				break
			}
			select {
			case <-readyCtx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
		cancelReady()
		if !ready {
			k.Stop()
			return nil, fmt.Errorf("authenticated probe listeners not ready")
		}
		select {
		case <-k.Done:
			k.Stop()
			return nil, fmt.Errorf("Mihomo exited during startup")
		default:
		}
		cleanup = false
		return k, nil
	}
	return nil, fmt.Errorf("kernel validation retry limit")
}
func (k *KernelInstance) Stop() {
	if k == nil {
		return
	}
	k.once.Do(func() { k.cancel(); <-k.Done; releasePorts(k.ports); os.RemoveAll(k.tempDir) })
}

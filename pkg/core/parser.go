package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type ProxyNode struct {
	ID, Name, Type, Server   string
	Port, LocalPort          int
	RawConfig                map[string]interface{}
	ProxyUser, ProxyPassword string
}
type ParseWarning struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func tryBase64Decode(s string) (string, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if b, e := encoding.DecodeString(s); e == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("invalid base64")
}
func ParseNodes(content string) ([]*ProxyNode, error) {
	nodes, _, e := ParseNodesDetailed(content, 1000)
	return nodes, e
}
func ParseNodesDetailed(content string, maxNodes int) ([]*ProxyNode, []ParseWarning, error) {
	content = strings.TrimSpace(content)
	if len(content) > 2<<20 {
		return nil, nil, fmt.Errorf("input exceeds 2 MiB")
	}
	if !strings.Contains(content, "://") && !strings.Contains(content, "proxies:") {
		if decoded, e := tryBase64Decode(content); e == nil {
			content = decoded
		}
	}
	var raw []map[string]interface{}
	var warnings []ParseWarning
	if strings.Contains(content, "proxies:") {
		var cfg struct {
			Proxies []map[string]interface{} `yaml:"proxies"`
		}
		if e := yaml.Unmarshal([]byte(content), &cfg); e != nil {
			return nil, nil, fmt.Errorf("invalid Clash YAML")
		}
		raw = cfg.Proxies
	} else {
		for i, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			p, e := parseURI(line)
			if e != nil {
				warnings = append(warnings, ParseWarning{fmt.Sprintf("input-%d", i+1), fmt.Sprintf("第 %d 行", i+1), e.Error()})
			} else {
				raw = append(raw, p)
			}
			if len(raw)+len(warnings) > maxNodes {
				return nil, nil, fmt.Errorf("maximum %d nodes", maxNodes)
			}
		}
	}
	if len(raw)+len(warnings) > maxNodes {
		return nil, nil, fmt.Errorf("maximum %d nodes", maxNodes)
	}
	used := map[string]bool{"DIRECT": true, "REJECT": true, "GLOBAL": true, "PROXIES": true}
	nodes := make([]*ProxyNode, 0, len(raw))
	for i, p := range raw {
		name, _ := p["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			name = fmt.Sprintf("Node-%d", i+1)
		}
		kind, _ := p["type"].(string)
		server, _ := p["server"].(string)
		port := number(p["port"])
		id := fmt.Sprintf("node-%d", i+1)
		if server == "" || port < 1 || port > 65535 || kind == "" {
			warnings = append(warnings, ParseWarning{id, name, "缺少协议/服务器或端口无效"})
			continue
		}
		unique := name
		for n := 2; used[unique]; n++ {
			unique = fmt.Sprintf("%s #%d", name, n)
		}
		used[unique] = true
		p["name"] = unique
		p["port"] = port
		nodes = append(nodes, &ProxyNode{ID: id, Name: unique, Type: kind, Server: server, Port: port, RawConfig: p})
	}
	if len(nodes) == 0 {
		return nil, warnings, fmt.Errorf("no valid nodes; supported URI: ss, trojan, vmess, vless, hysteria2, socks5, http")
	}
	return nodes, warnings, nil
}
func number(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		if x == float64(int(x)) {
			return int(x)
		}
	case json.Number:
		n, _ := strconv.Atoi(string(x))
		return n
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
func text(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func parseURI(raw string) (map[string]interface{}, error) {
	if strings.HasPrefix(raw, "vmess://") && !strings.Contains(strings.TrimPrefix(raw, "vmess://"), "@") {
		return parseVMess(strings.TrimPrefix(raw, "vmess://"))
	}
	if strings.HasPrefix(raw, "ss://") && !strings.Contains(strings.TrimPrefix(raw, "ss://"), "@") {
		parts := strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)
		decoded, e := tryBase64Decode(parts[0])
		if e != nil {
			return nil, fmt.Errorf("invalid SS encoding")
		}
		separator := strings.LastIndex(decoded, "@")
		if separator < 0 {
			return nil, fmt.Errorf("invalid SS encoding")
		}
		credentials, endpoint := decoded[:separator], decoded[separator+1:]
		cipher, password, ok := strings.Cut(credentials, ":")
		if !ok {
			return nil, fmt.Errorf("invalid SS credentials")
		}
		raw = "ss://" + url.UserPassword(cipher, password).String() + "@" + endpoint
		if len(parts) == 2 {
			raw += "#" + parts[1]
		}
	}
	u, e := url.Parse(raw)
	if e != nil {
		return nil, fmt.Errorf("invalid URI (details omitted)")
	}
	kind := strings.ToLower(u.Scheme)
	if kind == "socks" {
		kind = "socks5"
	}
	if kind == "hy2" {
		kind = "hysteria2"
	}
	if kind == "https" {
		kind = "http"
	}
	switch kind {
	case "ss", "trojan", "vless", "vmess", "hysteria2", "socks5", "http":
	default:
		return nil, fmt.Errorf("unsupported URI protocol")
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 && (kind == "trojan" || kind == "hysteria2") {
		port = 443
	}
	if u.Hostname() == "" || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid server or port")
	}
	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("%s-%s", kind, net.JoinHostPort(u.Hostname(), strconv.Itoa(port)))
	}
	p := map[string]interface{}{"name": name, "type": kind, "server": u.Hostname(), "port": port, "udp": true}
	q := u.Query()
	switch kind {
	case "ss":
		if u.User == nil {
			return nil, fmt.Errorf("SS credentials missing")
		}
		cipher := u.User.Username()
		password, has := u.User.Password()
		if !has {
			decoded, e := tryBase64Decode(cipher)
			if e != nil {
				return nil, fmt.Errorf("invalid SS credentials")
			}
			parts := strings.SplitN(decoded, ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid SS credentials")
			}
			cipher, password = parts[0], parts[1]
		}
		p["cipher"], p["password"] = cipher, password
		if plugin := q.Get("plugin"); plugin != "" {
			parts := strings.Split(plugin, ";")
			switch parts[0] {
			case "v2ray-plugin":
				p["plugin"] = "v2ray-plugin"
			case "obfs-local":
				p["plugin"] = "obfs"
			default:
				return nil, fmt.Errorf("unsupported SS plugin")
			}
			opts := map[string]interface{}{}
			for _, part := range parts[1:] {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					key := strings.TrimPrefix(kv[0], "obfs-")
					if key == "obfs" {
						key = "mode"
					}
					opts[key] = kv[1]
				} else {
					opts[part] = true
				}
			}
			p["plugin-opts"] = opts
		}
	case "trojan", "hysteria2":
		if u.User == nil || u.User.Username() == "" {
			return nil, fmt.Errorf("password missing")
		}
		p["password"] = u.User.Username()
		if password, has := u.User.Password(); has {
			p["password"] = u.User.Username() + ":" + password
		}
	case "vless", "vmess":
		if u.User == nil || u.User.Username() == "" {
			return nil, fmt.Errorf("UUID missing")
		}
		p["uuid"] = u.User.Username()
		if kind == "vless" {
			if flow := q.Get("flow"); flow != "" {
				p["flow"] = flow
			}
			if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
				p["encryption"] = encryption
			}
		} else {
			p["alterId"] = 0
			p["cipher"] = "auto"
		}
	case "socks5", "http":
		if u.User != nil {
			p["username"] = u.User.Username()
			if password, has := u.User.Password(); has {
				p["password"] = password
			}
		}
		if u.Scheme == "https" {
			p["tls"] = true
		}
	}
	if kind == "hysteria2" {
		if s := q.Get("obfs"); s != "" {
			p["obfs"] = s
		}
		if s := q.Get("obfs-password"); s != "" {
			p["obfs-password"] = s
		}
		if s := q.Get("mport"); s != "" {
			p["ports"] = s
		}
	}
	if e = applyTransport(p, q); e != nil {
		return nil, e
	}
	return p, nil
}
func applyTransport(p map[string]interface{}, q url.Values) error {
	kind := text(p["type"])
	security := q.Get("security")
	if security != "" && security != "none" && security != "tls" && security != "reality" {
		return fmt.Errorf("unsupported security mode")
	}
	tls := security == "tls" || security == "reality" || q.Get("tls") == "1" || q.Get("tls") == "tls"
	if kind == "trojan" || kind == "hysteria2" {
		tls = true
	}
	if tls {
		p["tls"] = true
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni != "" {
		if kind == "vless" || kind == "vmess" {
			p["servername"] = sni
		} else {
			p["sni"] = sni
		}
	}
	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" || q.Get("allowInsecure") == "true" {
		p["skip-cert-verify"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p["alpn"] = strings.Split(alpn, ",")
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}
	if security == "reality" {
		if q.Get("pbk") == "" {
			return fmt.Errorf("Reality public key missing")
		}
		p["reality-opts"] = map[string]interface{}{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
	}
	network := q.Get("type")
	if network == "" {
		network = q.Get("network")
	}
	if network == "" {
		network = "tcp"
	}
	if kind != "vless" && kind != "vmess" && kind != "trojan" {
		if network != "tcp" {
			return fmt.Errorf("transport not supported for protocol")
		}
		return nil
	}
	switch network {
	case "tcp":
		if h := q.Get("headerType"); h != "" && h != "none" {
			return fmt.Errorf("unsupported TCP header; use Clash YAML")
		}
	case "ws":
		p["network"] = "ws"
		opts := map[string]interface{}{"path": q.Get("path")}
		if q.Get("host") != "" {
			opts["headers"] = map[string]string{"Host": q.Get("host")}
		}
		p["ws-opts"] = opts
	case "grpc":
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]interface{}{"grpc-service-name": q.Get("serviceName")}
	case "h2":
		p["network"] = "h2"
		p["h2-opts"] = map[string]interface{}{"host": strings.Split(q.Get("host"), ","), "path": q.Get("path")}
	case "http":
		p["network"] = "http"
		p["http-opts"] = map[string]interface{}{"path": []string{q.Get("path")}, "headers": map[string]interface{}{"Host": strings.Split(q.Get("host"), ",")}}
	default:
		return fmt.Errorf("unsupported transport; use Clash YAML")
	}
	return nil
}
func parseVMess(encoded string) (map[string]interface{}, error) {
	decoded, e := tryBase64Decode(encoded)
	if e != nil {
		return nil, fmt.Errorf("invalid VMess encoding")
	}
	var v map[string]interface{}
	d := json.NewDecoder(strings.NewReader(decoded))
	d.UseNumber()
	if e = d.Decode(&v); e != nil {
		return nil, fmt.Errorf("invalid VMess JSON")
	}
	p := map[string]interface{}{"name": text(v["ps"]), "type": "vmess", "server": text(v["add"]), "port": number(v["port"]), "uuid": text(v["id"]), "alterId": number(v["aid"]), "cipher": text(v["scy"]), "udp": true}
	if p["uuid"] == "" {
		return nil, fmt.Errorf("VMess UUID missing")
	}
	if p["cipher"] == "" {
		p["cipher"] = "auto"
	}
	q := url.Values{}
	for from, to := range map[string]string{"net": "type", "host": "host", "path": "path", "sni": "sni", "tls": "tls", "alpn": "alpn", "fp": "fp", "type": "headerType"} {
		if s := text(v[from]); s != "" {
			q.Set(to, s)
		}
	}
	if text(v["net"]) == "grpc" {
		q.Set("serviceName", text(v["path"]))
	}
	if e = applyTransport(p, q); e != nil {
		return nil, e
	}
	return p, nil
}

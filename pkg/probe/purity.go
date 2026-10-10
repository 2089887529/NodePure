package probe

import (
	"strings"
)

type PurityAnalysis struct {
	IPType      string `json:"ip_type"`
	IPTypeLabel string `json:"ip_type_label"`
	Nativeness  string `json:"nativeness"`
	NativeLabel string `json:"native_label"`
	FraudScore  *int   `json:"fraud_score"`
	PurityScore *int   `json:"purity_score"`
	Grade       string `json:"grade"`
	RiskLevel   string `json:"risk_level"`
	RiskLabel   string `json:"risk_label"`
	Reason      string `json:"reason"`
	Confidence  string `json:"confidence"`
	Verified    bool   `json:"verified"`
}

// ASN/ISP hints are not evidence of reputation, native routing or residential use.
// No measured risk score is fabricated when a reputation source is unavailable.
func AnalyzePurity(info *IPInfo) *PurityAnalysis {
	p := &PurityAnalysis{IPType: "unknown", IPTypeLabel: "类型未知", Nativeness: "unknown", NativeLabel: "原生性未知", Grade: "unknown", RiskLevel: "unknown", RiskLabel: "风险未测量", Confidence: "unknown", Reason: "未接入可验证的 IP 风险及原生性数据源"}
	if info == nil || info.ISP == "" && info.Org == "" {
		return p
	}
	org := strings.ToLower(info.ISP + " " + info.Org)
	for _, k := range []string{"amazon", "google cloud", "microsoft", "digitalocean", "cloudflare", "linode", "hetzner", "ovh", "hosting", "datacenter", "vultr"} {
		if strings.Contains(org, k) {
			p.IPType = "datacenter"
			p.IPTypeLabel = "云/机房运营商（推测）"
			p.Confidence = "heuristic"
			return p
		}
	}
	for _, k := range []string{"comcast", "broadband", "chunghwa", "singtel", "softbank", "china telecom", "china unicom", "verizon", "charter", "cox communications", "hkbn", "pccw", "deutsche telekom"} {
		if strings.Contains(org, k) {
			p.IPType = "residential"
			p.IPTypeLabel = "住宅 ISP 线索（推测）"
			p.Confidence = "heuristic"
			return p
		}
	}
	return p
}

package analysis

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ResponseLayer string

const (
	LayerUnknown   ResponseLayer = "unknown"
	LayerTransport ResponseLayer = "transport_layer"
	LayerGateway   ResponseLayer = "gateway_layer"
	LayerRisk      ResponseLayer = "risk_layer"
	LayerBusiness  ResponseLayer = "business_layer"
)

type ResponseInput struct {
	HTTPStatus int `json:"httpStatus,omitempty"`
	Body       any `json:"body,omitempty"`
}

type Classification struct {
	Layer                  ResponseLayer `json:"layer"`
	Confidence             float64       `json:"confidence"`
	RiskPassedByClientRule *bool         `json:"riskPassedByClientRule,omitempty"`
	Reasons                []string      `json:"reasons"`
}

func ClassifyResponse(input ResponseInput) Classification {
	body := normalizeBody(input.Body)
	if body == nil {
		if input.HTTPStatus >= 500 {
			return Classification{Layer: LayerGateway, Confidence: 0.8, Reasons: []string{"HTTP status is 5xx"}}
		}
		if input.HTTPStatus >= 400 {
			return Classification{Layer: LayerTransport, Confidence: 0.7, Reasons: []string{fmt.Sprintf("HTTP status is %d", input.HTTPStatus)}}
		}
		return Classification{Layer: LayerUnknown, Confidence: 0.2, Reasons: []string{"response body is not a recognized JSON object"}}
	}

	data, _ := body["data"].(map[string]any)
	if risk, ok := data["risk"].(bool); ok && risk {
		passed := false
		return Classification{Layer: LayerRisk, Confidence: 0.98, RiskPassedByClientRule: &passed, Reasons: []string{"data.risk=true"}}
	}
	if explain := strings.ToUpper(stringValue(data["explain"])); strings.Contains(explain, "SCORE_REFUSE") {
		passed := false
		return Classification{Layer: LayerRisk, Confidence: 0.96, RiskPassedByClientRule: &passed, Reasons: []string{"data.explain contains SCORE_REFUSE"}}
	}

	if resultCode, ok := numericString(body["resultCode"]); ok {
		if resultCode == "999" && (body["data"] == nil || body["data"] == "") {
			passed := true
			return Classification{Layer: LayerBusiness, Confidence: 0.95, RiskPassedByClientRule: &passed, Reasons: []string{"resultCode=999", "data is null/empty", "no data.risk predicate"}}
		}
		return Classification{Layer: LayerBusiness, Confidence: 0.85, RiskPassedByClientRule: boolPtr(true), Reasons: []string{"top-level resultCode is present", "no risk predicate matched"}}
	}
	if code, ok := numericString(body["code"]); ok {
		if code == "0" {
			passed := true
			return Classification{Layer: LayerBusiness, Confidence: 0.82, RiskPassedByClientRule: &passed, Reasons: []string{"top-level code=0"}}
		}
		return Classification{Layer: LayerGateway, Confidence: 0.72, Reasons: []string{"non-zero top-level code", "no explicit risk predicate matched"}}
	}
	return Classification{Layer: LayerUnknown, Confidence: 0.25, Reasons: []string{"recognized JSON object but no layer discriminator"}}
}

func normalizeBody(body any) map[string]any {
	switch value := body.(type) {
	case map[string]any:
		return value
	case []byte:
		var out map[string]any
		if json.Unmarshal(value, &out) == nil {
			return out
		}
	case string:
		var out map[string]any
		if json.Unmarshal([]byte(value), &out) == nil {
			return out
		}
	}
	return nil
}

func numericString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v), strings.TrimSpace(v) != ""
	case float64:
		return fmt.Sprintf("%.0f", v), true
	case int:
		return fmt.Sprintf("%d", v), true
	case int64:
		return fmt.Sprintf("%d", v), true
	default:
		return "", false
	}
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func boolPtr(value bool) *bool { return &value }

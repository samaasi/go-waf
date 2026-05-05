package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type WafPolicySpec struct {
	BlockThreshold  int      `json:"blockThreshold"`
	EnableBotShield bool     `json:"enableBotShield"`
	BlockCountries  []string `json:"blockCountries"`
	AllowCountries  []string `json:"allowCountries"`
	Dlp             struct {
		Enabled bool   `json:"enabled"`
		Action  string `json:"action"`
	} `json:"dlp"`
}

type WafPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WafPolicySpec `json:"spec"`
}

type WafPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WafPolicy `json:"items"`
}

// DeepCopyObject is required for runtime.Object interface
func (in *WafPolicy) DeepCopyObject() runtime.Object {
	out := *in
	return &out
}

// DeepCopyObject is required for runtime.Object interface
func (in *WafPolicyList) DeepCopyObject() runtime.Object {
	out := *in
	return &out
}

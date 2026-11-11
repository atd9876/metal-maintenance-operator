// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"github.com/ironcore-dev/metal-maintenance-operator/api"
	maintenancev1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/maintenance/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// SecureBootConfigTemplate holds the fields of SecureBootConfigSpec that can be
// templated over many servers (all fields except ServerRef and
// CompletionConditionType, which are per-server and not meaningful at Set level).
type SecureBootConfigTemplate struct {
	// KeySecretRef names the Secret holding the Secure Boot key material.
	// +required
	KeySecretRef corev1.LocalObjectReference `json:"keySecretRef"`

	// DesiredState controls the top-level goal.
	// +kubebuilder:default=Enabled
	// +optional
	DesiredState SecureBootDesiredState `json:"desiredState,omitempty"`

	// ServerMaintenancePolicy controls whether maintenance windows require
	// owner approval before the server is parked.
	// +kubebuilder:default=Enforced
	// +kubebuilder:validation:Enum=OwnerApproval;Enforced
	// +optional
	ServerMaintenancePolicy maintenancev1alpha1.ServerMaintenancePolicy `json:"serverMaintenancePolicy,omitempty"`

	// RetryPolicy defines automatic retry behaviour on transient failures.
	// +optional
	RetryPolicy *api.RetryPolicy `json:"retryPolicy,omitempty"`

	// ProgressDeadlineSeconds is the maximum time in seconds to wait without
	// observable forward progress before a child resource is marked Failed.
	// +kubebuilder:default=3600
	// +optional
	ProgressDeadlineSeconds *int32 `json:"progressDeadlineSeconds,omitempty"`
}

// SecureBootConfigSetSpec defines the desired state of SecureBootConfigSet.
type SecureBootConfigSetSpec struct {
	// SecureBootConfigTemplate is applied to each matched server.
	// +required
	SecureBootConfigTemplate SecureBootConfigTemplate `json:"secureBootConfigTemplate"`

	// ServerSelector selects the servers to manage. An empty selector matches
	// no servers.
	// +required
	ServerSelector metav1.LabelSelector `json:"serverSelector"`
}

// SecureBootConfigSetStatus defines the observed state of SecureBootConfigSet.
type SecureBootConfigSetStatus struct {
	// FullyLabeledServers is the number of servers currently selected.
	FullyLabeledServers int32 `json:"fullyLabeledServers,omitempty"`
	// AvailableSecureBootConfigs is the number of child SecureBootConfigs created.
	AvailableSecureBootConfigs int32 `json:"availableSecureBootConfigs,omitempty"`
	// PendingSecureBootConfigs is the count of children in Pending state.
	PendingSecureBootConfigs int32 `json:"pendingSecureBootConfigs,omitempty"`
	// InProgressSecureBootConfigs is the count of children actively reconciling.
	InProgressSecureBootConfigs int32 `json:"inProgressSecureBootConfigs,omitempty"`
	// CompletedSecureBootConfigs is the count of children that reached Enabled or Disabled.
	CompletedSecureBootConfigs int32 `json:"completedSecureBootConfigs,omitempty"`
	// FailedSecureBootConfigs is the count of children in Failed state.
	FailedSecureBootConfigs int32 `json:"failedSecureBootConfigs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=sbcs
// +kubebuilder:printcolumn:name="DesiredState",type="string",JSONPath=".spec.secureBootConfigTemplate.desiredState"
// +kubebuilder:printcolumn:name="TotalServers",type="string",JSONPath=".status.fullyLabeledServers"
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.availableSecureBootConfigs"
// +kubebuilder:printcolumn:name="Completed",type="string",JSONPath=".status.completedSecureBootConfigs"
// +kubebuilder:printcolumn:name="Failed",type="string",JSONPath=".status.failedSecureBootConfigs"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SecureBootConfigSet stamps out one SecureBootConfig per server matching serverSelector.
type SecureBootConfigSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecureBootConfigSetSpec   `json:"spec,omitempty"`
	Status SecureBootConfigSetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecureBootConfigSetList contains a list of SecureBootConfigSet.
type SecureBootConfigSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecureBootConfigSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecureBootConfigSet{}, &SecureBootConfigSetList{})
		return nil
	})
}

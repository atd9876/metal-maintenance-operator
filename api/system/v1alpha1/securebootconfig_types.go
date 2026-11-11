// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"github.com/ironcore-dev/metal-maintenance-operator/api"
	maintenancev1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/maintenance/v1alpha1"
	metalv1alpha1 "github.com/ironcore-dev/metal-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// SecureBootDesiredState is the top-level goal for the SecureBootConfig controller.
// +kubebuilder:validation:Enum=Enabled;Disabled
type SecureBootDesiredState string

const (
	SecureBootDesiredStateEnabled  SecureBootDesiredState = "Enabled"
	SecureBootDesiredStateDisabled SecureBootDesiredState = "Disabled"
)

// SecureBootConfigState is the top-level lifecycle state.
// +kubebuilder:validation:Enum=Pending;ClearingKeys;Enrolling;Enrolled;Enabling;Enabled;Disabled;Failed
type SecureBootConfigState string

const (
	SecureBootConfigStatePending      SecureBootConfigState = "Pending"
	SecureBootConfigStateClearingKeys SecureBootConfigState = "ClearingKeys"
	SecureBootConfigStateEnrolling    SecureBootConfigState = "Enrolling"
	SecureBootConfigStateEnrolled     SecureBootConfigState = "Enrolled"
	SecureBootConfigStateEnabling     SecureBootConfigState = "Enabling"
	SecureBootConfigStateEnabled      SecureBootConfigState = "Enabled"
	SecureBootConfigStateDisabled     SecureBootConfigState = "Disabled"
	SecureBootConfigStateFailed       SecureBootConfigState = "Failed"
)

// SecureBootConfigSpec defines the desired state of SecureBootConfig.
type SecureBootConfigSpec struct {
	// ServerRef is the server to manage Secure Boot on. Immutable once set.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="serverRef is immutable"
	// +required
	ServerRef *corev1.LocalObjectReference `json:"serverRef"`

	// KeySecretRef names the Secret holding the Secure Boot key material.
	// The Secret must contain pk.crt, kek.crt, and one or more db.crt.N
	// and/or db.sha256.N entries. Updating the Secret and annotating with
	// metal.ironcore.dev/operation=re-enroll triggers re-enrollment.
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
	// observable forward progress before the resource is marked Failed.
	// +kubebuilder:default=3600
	// +optional
	ProgressDeadlineSeconds *int32 `json:"progressDeadlineSeconds,omitempty"`

	// ReadinessGates lists Server conditions that must be True before this
	// controller starts acting. Evaluated once at the Pending→active boundary.
	// +optional
	ReadinessGates []metalv1alpha1.ConditionRequirement `json:"readinessGates,omitempty"`

	// CompletionConditionType, if set, is the condition Type patched onto the
	// Server once this resource reaches its terminal success state (Enabled or
	// Disabled). Immutable once set.
	// +optional
	// +kubebuilder:validation:XValidation:rule="oldSelf == '' || self == oldSelf",message="completionConditionType is immutable once set"
	CompletionConditionType string `json:"completionConditionType,omitempty"`
}

// SecureBootConfigStatus defines the observed state of SecureBootConfig.
type SecureBootConfigStatus struct {
	// State is the current reconciliation state.
	// +optional
	State SecureBootConfigState `json:"state,omitempty"`

	// ServerMaintenanceRef is the maintenance window currently held, if any.
	// +optional
	ServerMaintenanceRef *metalv1alpha1.ObjectReference `json:"serverMaintenanceRef,omitempty"`

	// CurrentMode is the SecureBootMode last read from the BMC.
	// +optional
	CurrentMode string `json:"currentMode,omitempty"`

	// EnabledKeySecret records the ResourceVersion of the KeySecretRef Secret
	// at the time of the last successful enrollment, used to detect when the
	// Secret has been updated and re-enrollment is needed.
	// +optional
	EnabledKeySecret string `json:"enabledKeySecret,omitempty"`

	// RebootIssuedForState records the State in which the last BMC reboot was
	// issued, used to determine whether the post-reboot verification phase has
	// been reached. Reset to "" whenever State advances to a new value.
	// +optional
	RebootIssuedForState SecureBootConfigState `json:"rebootIssuedForState,omitempty"`

	// LastEnabledTime is when the Enabled state was last reached.
	// +optional
	LastEnabledTime *metav1.Time `json:"lastEnabledTime,omitempty"`

	// LastProgressTime records the last observed forward progress, used with
	// ProgressDeadlineSeconds to detect stalled reconciliation.
	// +optional
	LastProgressTime *metav1.Time `json:"lastProgressTime,omitempty"`

	// FailedAttempts counts automatic retries after entering Failed state.
	// +optional
	FailedAttempts int32 `json:"failedAttempts,omitempty"`

	// ObservedGeneration is the spec generation last acted on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds per-phase conditions for observability.
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=sbc
// +kubebuilder:printcolumn:name="Server",type="string",JSONPath=".spec.serverRef.name"
// +kubebuilder:printcolumn:name="DesiredState",type="string",JSONPath=".spec.desiredState"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SecureBootConfig manages UEFI Secure Boot enrollment and state on a single server.
type SecureBootConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecureBootConfigSpec   `json:"spec,omitempty"`
	Status SecureBootConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecureBootConfigList contains a list of SecureBootConfig.
type SecureBootConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecureBootConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SecureBootConfig{}, &SecureBootConfigList{})
		return nil
	})
}

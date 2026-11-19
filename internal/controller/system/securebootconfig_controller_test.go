// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package system

import (
	maintenancev1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/maintenance/v1alpha1"
	systemv1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/system/v1alpha1"
	constants "github.com/ironcore-dev/metal-maintenance-operator/internal/constants"
	metalv1alpha1 "github.com/ironcore-dev/metal-operator/api/v1alpha1"

	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// mockSystemPath is the Redfish system path used by the default mock server fixture.
const mockSystemPath = "/redfish/v1/Systems/437XR1138R2"

// testKeySecret returns a minimal Secret containing the four key material
// entries expected by enrollKeys: db.crt, kek.crt, pk.crt, and a dbx hash.
func testKeySecret(ns, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Data: map[string][]byte{
			"db.crt":     []byte("-----BEGIN CERTIFICATE-----\nMIIBdb==\n-----END CERTIFICATE-----\n"),
			"kek.crt":    []byte("-----BEGIN CERTIFICATE-----\nMIIBkek==\n-----END CERTIFICATE-----\n"),
			"pk.crt":     []byte("-----BEGIN CERTIFICATE-----\nMIIBpk==\n-----END CERTIFICATE-----\n"),
			"dbx.sha256": []byte("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"),
		},
	}
}

var _ = Describe("SecureBootConfig Controller", func() {
	ns, ms, msPort := SetupTestWithMock()

	var (
		server    *metalv1alpha1.Server
		bmcSecret *metalv1alpha1.BMCSecret
		keySecret *corev1.Secret
	)

	BeforeEach(func(ctx SpecContext) {
		By("Creating a BMCSecret")
		bmcSecret = &metalv1alpha1.BMCSecret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-bmc-",
				Namespace:    ns.Name,
			},
			Data: map[string][]byte{
				metalv1alpha1.BMCSecretUsernameKeyName: []byte("admin"),
				metalv1alpha1.BMCSecretPasswordKeyName: []byte("adminpass"),
			},
		}
		Expect(k8sClient.Create(ctx, bmcSecret)).To(Succeed())

		By("Creating a Server")
		server = &metalv1alpha1.Server{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
			},
			Spec: metalv1alpha1.ServerSpec{
				SystemUUID: "38947555-7742-3448-3784-823347823834",
				BMC: &metalv1alpha1.BMCAccess{
					Protocol: metalv1alpha1.Protocol{
						Name: metalv1alpha1.ProtocolRedfishLocal,
						Port: *msPort,
					},
					Address: MockServerIP,
					BMCSecretRef: corev1.LocalObjectReference{
						Name: bmcSecret.Name,
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, server)).To(Succeed())

		By("Waiting for SystemURI to be discovered")
		Eventually(Object(server)).Should(
			HaveField("Spec.SystemURI", Not(BeEmpty())),
		)

		By("Setting Server state to Available")
		Eventually(UpdateStatus(server, func() {
			server.Status.State = metalv1alpha1.ServerStateAvailable
		})).Should(Succeed())

		By("Creating a key Secret")
		keySecret = testKeySecret(ns.Name, "test-keys")
		Expect(k8sClient.Create(ctx, keySecret)).To(Succeed())
	})

	AfterEach(func(ctx SpecContext) {
		Expect(k8sClient.Delete(ctx, server)).To(Succeed())
		Expect(k8sClient.Delete(ctx, bmcSecret)).To(Succeed())
		Expect(k8sClient.Delete(ctx, keySecret)).To(Succeed())
		EnsureCleanState()
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Happy path: SetupMode → Enroll → Enable → Enabled
	// ──────────────────────────────────────────────────────────────────────────

	It("should reach Enabled state from SetupMode (no prior PK)", func(ctx SpecContext) {
		By("Configuring mock: system already in SetupMode (no PK installed)")
		(*ms).SetSecureBootMode(mockSystemPath, "SetupMode")

		By("Creating a SecureBootConfig")
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateEnabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for Enrolling state (SetupMode detected, skipping key clear)")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnrolling),
		)

		By("Waiting for ServerMaintenance to be created")
		sm := &maintenancev1alpha1.ServerMaintenance{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: sbc.Name},
		}
		Eventually(Get(sm)).Should(Succeed())

		By("Waiting for ServerMaintenance to enter InMaintenance")
		Eventually(Object(sm)).Should(
			HaveField("Status.State", maintenancev1alpha1.ServerMaintenanceStateInMaintenance),
		)

		By("Simulating post-enrollment reboot: set CurrentBoot=Enabled then transition mock to UserMode")
		// Set CurrentBoot=true before transitioning to UserMode so the controller
		// sees the correct state when it checks EnabledOnBoot in handleEnabling.
		(*ms).SetSecureBootCurrentBoot(mockSystemPath, true)
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")

		By("Waiting for Enabling state (Enrolled is an instant passthrough)")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabling),
		)

		By("Waiting for Enabled state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabled),
		)

		By("Verifying server label is set")
		Eventually(Object(server)).Should(
			HaveField("Labels", HaveKeyWithValue(labelSecureBootEnabled, "true")),
		)

		By("Verifying ServerMaintenance has been deleted")
		Eventually(Get(sm)).Should(Satisfy(apierrors.IsNotFound))

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Happy path with existing PK: UserMode → ClearKeys → Enroll → Enable
	// ──────────────────────────────────────────────────────────────────────────

	It("should clear keys first when SB is off in UserMode", func(ctx SpecContext) {
		By("Configuring mock: SB disabled, UserMode (fixture default — foreign PK installed)")
		// Default fixture: SecureBootEnable=false, SecureBootMode=UserMode

		By("Creating a SecureBootConfig")
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateEnabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for ClearingKeys state (UserMode with SB off → must clear first)")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateClearingKeys),
		)

		By("Verifying key clear was issued: mock should be in SetupMode")
		// handleClearingKeys calls ResetSecureBootKeys(DeleteAllKeys) which
		// transitions the mock to SetupMode immediately (no reboot needed for mode change).
		Eventually(func() string {
			return (*ms).GetSecureBootState(mockSystemPath).Mode
		}).Should(Equal("SetupMode"))

		By("Waiting for Enrolling state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnrolling),
		)

		By("Simulating post-enrollment reboot: set CurrentBoot then transition to UserMode")
		(*ms).SetSecureBootCurrentBoot(mockSystemPath, true)
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")

		By("Waiting for Enabling state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabling),
		)

		By("Waiting for Enabled state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabled),
		)

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Disable path: SB enabled → DesiredState=Disabled → Disabled
	// ──────────────────────────────────────────────────────────────────────────

	It("should reach Disabled state when desiredState=Disabled and SB keys are cleared", func(ctx SpecContext) {
		By("Configuring mock: UserMode SB (needs clearing to reach Disabled)")
		// Fixture default: UserMode, SB off — controller sees UserMode != SetupMode, transitions to ClearingKeys.

		By("Creating a SecureBootConfig with DesiredState=Disabled")
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateDisabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for ClearingKeys state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateClearingKeys),
		)

		By("Waiting for SetupMode to be reached on mock")
		Eventually(func() string {
			return (*ms).GetSecureBootState(mockSystemPath).Mode
		}).Should(Equal("SetupMode"))

		By("Waiting for Disabled state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateDisabled),
		)

		By("Verifying server label is set to false")
		Eventually(Object(server)).Should(
			HaveField("Labels", HaveKeyWithValue(labelSecureBootEnabled, "false")),
		)

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	It("should reach FactoryDefault state when desiredState=FactoryDefault", func(ctx SpecContext) {
		By("Configuring mock: UserMode with SB enabled (needs factory reset)")
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")
		(*ms).SetSecureBootEnable(mockSystemPath, true)

		By("Creating a SecureBootConfig with DesiredState=FactoryDefault")
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateFactoryDefault,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for ResettingKeys state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateResettingKeys),
		)

		By("Waiting for Secure Boot to be disabled on mock after factory reset")
		Eventually(func() bool {
			return (*ms).GetSecureBootState(mockSystemPath).Enabled
		}).Should(BeFalse())

		By("Waiting for FactoryDefault state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateFactoryDefault),
		)

		By("Verifying server label is set to false")
		Eventually(Object(server)).Should(
			HaveField("Labels", HaveKeyWithValue(labelSecureBootEnabled, "false")),
		)

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	It("should transition Enabled → FactoryDefault when desiredState is changed", func(ctx SpecContext) {
		By("Reaching Enabled from SetupMode")
		(*ms).SetSecureBootMode(mockSystemPath, "SetupMode")

		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateEnabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnrolling),
		)
		By("Simulating post-enrollment reboot")
		(*ms).SetSecureBootCurrentBoot(mockSystemPath, true)
		(*ms).SetSecureBootEnable(mockSystemPath, true)
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabling),
		)
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabled),
		)

		By("Changing DesiredState to FactoryDefault")
		Eventually(Update(sbc, func() {
			sbc.Spec.DesiredState = systemv1alpha1.SecureBootDesiredStateFactoryDefault
		})).Should(Succeed())

		By("Waiting for ResettingKeys state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateResettingKeys),
		)

		By("Waiting for Secure Boot disabled on mock after factory reset")
		Eventually(func() bool {
			return (*ms).GetSecureBootState(mockSystemPath).Enabled
		}).Should(BeFalse())

		By("Waiting for FactoryDefault state")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateFactoryDefault),
		)

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Disabled → Enabled transition on DesiredState change
	// ──────────────────────────────────────────────────────────────────────────

	It("should re-enable SB when desiredState is changed from Disabled to Enabled", func(ctx SpecContext) {
		By("Starting from SetupMode (already disabled/no keys)")
		(*ms).SetSecureBootMode(mockSystemPath, "SetupMode")

		By("Creating a SecureBootConfig with DesiredState=Disabled while already in SetupMode")
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateDisabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for Disabled state (SetupMode + Disabled = already done)")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateDisabled),
		)

		By("Updating DesiredState to Enabled")
		Eventually(Update(sbc, func() {
			sbc.Spec.DesiredState = systemv1alpha1.SecureBootDesiredStateEnabled
		})).Should(Succeed())

		By("Waiting for Enrolling state (re-enabled from Disabled, still in SetupMode)")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnrolling),
		)

		By("Simulating post-enrollment reboot: set CurrentBoot then transition to UserMode")
		(*ms).SetSecureBootCurrentBoot(mockSystemPath, true)
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")

		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabling))
		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabled))

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Drift detection: hardware SB disabled while in Enabled state
	// ──────────────────────────────────────────────────────────────────────────

	It("should detect hardware drift and re-enroll when SB is disabled on hardware", func(ctx SpecContext) {
		By("Starting from SetupMode to reach Enabled quickly")
		(*ms).SetSecureBootMode(mockSystemPath, "SetupMode")

		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateEnabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Driving to Enabled state")
		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnrolling))
		(*ms).SetSecureBootCurrentBoot(mockSystemPath, true)
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")
		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabling))
		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabled))

		By("Simulating hardware drift: SB disabled on BMC")
		// PATCH the mock's SecureBootEnable to false — the controller's drift
		// check in handleEnabled calls GetSecureBootState and compares Enabled.
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")
		// Also clear the Enabled flag in the mock via ResetSecureBootKeys so
		// GetSecureBootState returns Enabled=false.
		(*ms).ResetSecureBootState(mockSystemPath)
		// Fixture default: SecureBootEnable=false, UserMode.

		By("Waiting for drift to trigger re-enrollment (Pending is a fast passthrough, so check ClearingKeys)")
		// Pending→ClearingKeys happens within one resync cycle (10ms); assert the
		// observable endpoint rather than the fleeting intermediate state.
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateClearingKeys),
		)

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Retry annotation recovers from Failed state
	// ──────────────────────────────────────────────────────────────────────────

	It("should recover from Failed state when retry annotation is set", func(ctx SpecContext) {
		By("Manually forcing Failed state by creating SBC with a bad key secret name")
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: "nonexistent-secret"},
				DesiredState: systemv1alpha1.SecureBootDesiredStateEnabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for Enrolling state — SB fixture is SetupMode so controller goes to Enroll")
		// The mock starts with UserMode (fixture default), so controller goes to ClearingKeys.
		// After clearing, it tries to enroll — but the secret doesn't exist, so it fails.
		// We just need to wait for any Failed transition.
		// First: set SetupMode so controller skips ClearingKeys and goes straight to Enrolling.
		(*ms).SetSecureBootMode(mockSystemPath, "SetupMode")

		By("Waiting for Failed state due to missing secret")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateFailed),
		)

		By("Creating the missing secret")
		Expect(k8sClient.Create(ctx, testKeySecret(ns.Name, "nonexistent-secret"))).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			s := &corev1.Secret{}
			s.Name = "nonexistent-secret"
			s.Namespace = ns.Name
			_ = k8sClient.Delete(ctx, s)
		})

		By("Setting retry annotation on the SecureBootConfig")
		Eventually(Update(sbc, func() {
			if sbc.Annotations == nil {
				sbc.Annotations = make(map[string]string)
			}
			sbc.Annotations[constants.OperationAnnotation] = constants.OperationAnnotationRetry
		})).Should(Succeed())

		// Pending is a fast passthrough (10ms resync); skip to the first stable
		// state produced by re-evaluation (SetupMode → Enrolling).
		By("Waiting for Enrolling state after retry")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnrolling),
		)

		By("Simulating post-enrollment reboot")
		(*ms).SetSecureBootCurrentBoot(mockSystemPath, true)
		(*ms).SetSecureBootMode(mockSystemPath, "UserMode")
		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabling))
		Eventually(Object(sbc)).Should(HaveField("Status.State", systemv1alpha1.SecureBootConfigStateEnabled))

		By("Cleaning up")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))
	})

	// ──────────────────────────────────────────────────────────────────────────
	// Deletion cleans up ServerMaintenance
	// ──────────────────────────────────────────────────────────────────────────

	It("should clean up ServerMaintenance when SecureBootConfig is deleted during ClearingKeys", func(ctx SpecContext) {
		sbc := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sb-",
				Namespace:    ns.Name,
			},
			Spec: systemv1alpha1.SecureBootConfigSpec{
				ServerRef:    &corev1.LocalObjectReference{Name: server.Name},
				KeySecretRef: corev1.LocalObjectReference{Name: keySecret.Name},
				DesiredState: systemv1alpha1.SecureBootDesiredStateEnabled,
			},
		}
		Expect(k8sClient.Create(ctx, sbc)).To(Succeed())

		By("Waiting for ClearingKeys state so a ServerMaintenance is created")
		Eventually(Object(sbc)).Should(
			HaveField("Status.State", systemv1alpha1.SecureBootConfigStateClearingKeys),
		)
		sm := &maintenancev1alpha1.ServerMaintenance{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: sbc.Name},
		}
		Eventually(Get(sm)).Should(Succeed())

		By("Deleting the SecureBootConfig")
		Expect(k8sClient.Delete(ctx, sbc)).To(Succeed())

		By("Verifying that the SecureBootConfig is removed")
		Eventually(Get(sbc)).Should(Satisfy(apierrors.IsNotFound))

		By("Verifying that the ServerMaintenance is also removed")
		Eventually(Get(sm)).Should(Satisfy(apierrors.IsNotFound))
	})
})

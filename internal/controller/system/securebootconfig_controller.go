// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ironcore-dev/controller-utils/clientutils"
	"github.com/ironcore-dev/controller-utils/conditionutils"
	maintenancev1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/maintenance/v1alpha1"
	systemv1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/system/v1alpha1"
	constants "github.com/ironcore-dev/metal-maintenance-operator/internal/constants"
	utils "github.com/ironcore-dev/metal-maintenance-operator/internal/utils"
	metalv1alpha1 "github.com/ironcore-dev/metal-operator/api/v1alpha1"
	"github.com/ironcore-dev/metal-operator/bmc"
	"github.com/ironcore-dev/metal-operator/pkg/bmcutils"
	"github.com/stmcginnis/gofish/schemas"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

const (
	SecureBootConfigFinalizer = "system.metal.ironcore.dev/securebootconfig"

	// Server label applied once Secure Boot is confirmed active.
	labelSecureBootEnabled = "metal.ironcore.dev/secure-boot-enabled"

	// Annotation value on SecureBootConfig that triggers re-enrollment.
	operationReEnroll = "re-enroll"
)

// isBMCLocked returns true when the BMC rejected the request because a
// concurrent power operation has the system locked (HTTP 409 resource locked).
// The lock is transient (cleared after the power cycle completes, typically
// within 100 ms); callers should requeue quickly rather than returning an error.
func isBMCLocked(err error) bool {
	return err != nil && strings.Contains(err.Error(), "409")
}

// isBMCBusy returns true when the BMC is temporarily busy and the operation
// should be retried rather than failed permanently. Covers:
//   - HTTP 503: Dell iDRAC busy (e.g. mid-boot Settings resource).
//   - UnableToModifyDuringSystemPOST: HPE iLO rejects SB changes while the
//     system is in POST; the caller should wait and retry.
func isBMCBusy(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "503") ||
		strings.Contains(err.Error(), "UnableToModifyDuringSystemPOST") ||
		strings.Contains(err.Error(), "EOF"))
}

// SecureBootConfigReconciler reconciles a SecureBootConfig object.
type SecureBootConfigReconciler struct {
	client.Client
	ManagerNamespace   string
	DefaultProtocol    metalv1alpha1.ProtocolScheme
	SkipCertValidation bool
	Scheme             *runtime.Scheme
	BMCOptions         bmc.Options
	ResyncInterval     time.Duration
	Conditions         *conditionutils.Accessor
	// PostStuckTimeout is how long the controller waits in Enabling (before the
	// reboot is issued) before concluding the server is stuck in POST and issuing
	// a ForceOff to unblock iLO.
	PostStuckTimeout time.Duration
}

// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=servers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=maintenance.metal.ironcore.dev,resources=servermaintenances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=maintenance.metal.ironcore.dev,resources=servermaintenances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *SecureBootConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	sbc := &systemv1alpha1.SecureBootConfig{}
	if err := r.Get(ctx, req.NamespacedName, sbc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.V(1).Info("Reconciling SecureBootConfig")
	return r.reconcileExists(ctx, sbc)
}

func (r *SecureBootConfigReconciler) reconcileExists(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) (ctrl.Result, error) {
	if !sbc.DeletionTimestamp.IsZero() {
		return r.delete(ctx, sbc)
	}
	return r.reconcile(ctx, sbc)
}

func (r *SecureBootConfigReconciler) delete(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) (ctrl.Result, error) {
	if err := r.cleanupServerMaintenance(ctx, sbc); err != nil {
		return ctrl.Result{}, err
	}
	if modified, err := clientutils.PatchEnsureNoFinalizer(ctx, r.Client, sbc, SecureBootConfigFinalizer); err != nil || modified {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *SecureBootConfigReconciler) reconcile(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	if utils.ShouldIgnoreReconciliation(sbc) {
		log.V(1).Info("Skipped SecureBootConfig reconciliation")
		return ctrl.Result{}, nil
	}

	if modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, sbc, SecureBootConfigFinalizer); err != nil || modified {
		return ctrl.Result{}, err
	}

	if sbc.Spec.ServerRef == nil {
		return ctrl.Result{}, fmt.Errorf("SecureBootConfig has no serverRef")
	}
	server, err := utils.GetServerByName(ctx, r.Client, sbc.Spec.ServerRef.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to fetch server: %w", err)
	}

	// Acquire the BMC client once for states that need it. States that never
	// touch the BMC (Enrolled, Disabled, Failed) receive nil and must not use it.
	var bmcClient bmc.BMC
	if needsBMC(sbc.Status.State) {
		var logout func()
		var ok bool
		bmcClient, logout, ok, err = r.getBMCClient(ctx, sbc, server)
		if err != nil {
			if isBMCLocked(err) {
				return ctrl.Result{RequeueAfter: 150 * time.Millisecond}, nil
			}
			return ctrl.Result{}, err
		}
		if !ok {
			// BMC unavailable — requeue.
			return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
		}
		defer logout()
	}

	if err := r.transitionState(ctx, sbc, server, bmcClient); err != nil {
		if isBMCLocked(err) {
			return ctrl.Result{RequeueAfter: 150 * time.Millisecond}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
}

// needsBMC reports whether the given state requires a BMC connection.
func needsBMC(state systemv1alpha1.SecureBootConfigState) bool {
	switch state {
	case systemv1alpha1.SecureBootConfigStateClearingKeys,
		systemv1alpha1.SecureBootConfigStateEnrolling,
		systemv1alpha1.SecureBootConfigStateEnabling,
		systemv1alpha1.SecureBootConfigStateResettingKeys,
		systemv1alpha1.SecureBootConfigStateEnabled,
		"", systemv1alpha1.SecureBootConfigStatePending:
		return true
	}
	return false
}

func (r *SecureBootConfigReconciler) transitionState(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	switch sbc.Status.State {
	case "", systemv1alpha1.SecureBootConfigStatePending:
		return r.handlePending(ctx, sbc, server, bmcClient)

	case systemv1alpha1.SecureBootConfigStateClearingKeys:
		return r.handleClearingKeys(ctx, sbc, server, bmcClient)

	case systemv1alpha1.SecureBootConfigStateEnrolling:
		return r.handleEnrolling(ctx, sbc, server, bmcClient)

	case systemv1alpha1.SecureBootConfigStateEnrolled:
		// Immediately transition to Enabling — no external event needed.
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateEnabling, nil)

	case systemv1alpha1.SecureBootConfigStateEnabling:
		return r.handleEnabling(ctx, sbc, server, bmcClient)

	case systemv1alpha1.SecureBootConfigStateResettingKeys:
		return r.handleResettingKeys(ctx, sbc, server, bmcClient)

	case systemv1alpha1.SecureBootConfigStateEnabled:
		return r.handleEnabled(ctx, sbc, server, bmcClient)

	case systemv1alpha1.SecureBootConfigStateDisabled:
		return r.handleDisabled(ctx, sbc)

	case systemv1alpha1.SecureBootConfigStateFactoryDefault:
		return r.handleFactoryDefault(ctx, sbc)

	case systemv1alpha1.SecureBootConfigStateFailed:
		return r.handleFailed(ctx, sbc)
	}

	log.V(1).Info("Unknown SecureBootConfig state", "state", sbc.Status.State)
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// State handlers
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigReconciler) handlePending(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	// Fast path: re-enroll annotation — no BMC call needed.
	if ann := sbc.Annotations[constants.OperationAnnotation]; ann == operationReEnroll {
		base := sbc.DeepCopy()
		delete(sbc.Annotations, constants.OperationAnnotation)
		if err := r.Patch(ctx, sbc, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("failed to remove re-enroll annotation: %w", err)
		}
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateClearingKeys, nil)
	}

	sbManager, err := r.getSecureBootManager(ctx, sbc, bmcClient)
	if err != nil {
		return err
	}

	sbState, err := sbManager.GetSecureBootState(ctx, server.Spec.SystemURI)
	if err != nil {
		if errors.Is(err, bmc.ErrNotSupported) {
			return r.failWith(ctx, sbc, constants.ReasonSBNotSupported, "BMC does not support Secure Boot management")
		}
		if isBMCBusy(err) {
			log.V(1).Info("BMC busy reading Secure Boot state in Pending — retrying", "error", err)
			return nil
		}
		return fmt.Errorf("failed to read Secure Boot state: %w", err)
	}

	desired := sbc.Spec.DesiredState
	if desired == "" {
		desired = systemv1alpha1.SecureBootDesiredStateEnabled
	}

	if desired == systemv1alpha1.SecureBootDesiredStateDisabled {
		if !sbState.Enabled && sbState.Mode == bmc.SecureBootModeSetup {
			log.V(1).Info("Secure Boot already disabled and keys cleared — transitioning to Disabled")
			return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateDisabled, nil)
		}
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateClearingKeys, nil)
	}

	if desired == systemv1alpha1.SecureBootDesiredStateFactoryDefault {
		if !sbState.Enabled && sbState.Policy == bmc.SecureBootPolicyStandard {
			log.V(1).Info("Secure Boot already at factory default — transitioning to FactoryDefault")
			return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateFactoryDefault, nil)
		}
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateResettingKeys, nil)
	}

	// DesiredState = Enabled
	if sbState.Enabled && sbState.Mode == bmc.SecureBootModeUser {
		keySecret, err := r.getKeySecret(ctx, sbc)
		if err != nil {
			return err
		}
		if sbc.Status.EnabledKeySecret == keySecret.ResourceVersion {
			log.V(1).Info("Secure Boot already enabled with matching keys — transitioning to Enabled")
			return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateEnabled, nil)
		}
		log.V(1).Info("Secure Boot enabled but keys may differ — clearing to re-enroll")
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateClearingKeys, nil)
	}
	if sbState.Mode == bmc.SecureBootModeSetup {
		log.V(1).Info("SetupMode detected — transitioning to Enrolling")
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateEnrolling, nil)
	}
	// UserMode with foreign PK, or SB off — need to clear first.
	return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateClearingKeys, nil)
}

func (r *SecureBootConfigReconciler) handleClearingKeys(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	sbManager, err := r.getSecureBootManager(ctx, sbc, bmcClient)
	if err != nil {
		return err
	}

	active, err := r.ensureMaintenance(ctx, sbc, server)
	if err != nil {
		return err
	}
	if !active {
		return nil // waiting for maintenance window
	}

	if sbc.Status.RebootIssuedForState != systemv1alpha1.SecureBootConfigStateClearingKeys {
		// Phase A: ensure the platform permits custom key enrollment, disable SB,
		// then reset all keys.
		if err := sbManager.EnsureCustomKeyPolicy(ctx, server.Spec.SystemURI); err != nil {
			if isBMCBusy(err) {
				log.V(1).Info("BMC busy (503) during EnsureCustomKeyPolicy — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBClearFailed, fmt.Sprintf("failed to set custom key policy: %v", err))
		}
		if err := sbManager.SetSecureBootEnabled(ctx, server.Spec.SystemURI, false); err != nil {
			if isBMCBusy(err) {
				log.V(1).Info("BMC busy (503) during SetSecureBootEnabled(false) in ClearingKeys — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBClearFailed, fmt.Sprintf("failed to disable Secure Boot: %v", err))
		}
		if err := sbManager.ResetSecureBootKeys(ctx, server.Spec.SystemURI, bmc.SecureBootResetDeleteAllKeys); err != nil {
			if isBMCBusy(err) {
				log.V(1).Info("BMC busy during ResetSecureBootKeys in ClearingKeys — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBClearFailed, fmt.Sprintf("failed to reset Secure Boot keys: %v", err))
		}
		if err := bmcClient.SetBootOverrideContinuous(ctx, server.Spec.SystemURI); err != nil {
			log.V(1).Info("Could not set continuous PXE override; rebooting without it", "error", err)
		}
		log.V(1).Info("Secure Boot disabled and keys cleared — issuing reboot")
		if err := r.rebootServer(ctx, server, bmcClient); err != nil {
			return fmt.Errorf("failed to reboot server: %w", err)
		}
		return r.markRebootIssued(ctx, sbc)
	}

	// Phase B: verify SetupMode after reboot.
	sbState, err := sbManager.GetSecureBootState(ctx, server.Spec.SystemURI)
	if err != nil {
		if isBMCBusy(err) {
			log.V(1).Info("BMC busy reading Secure Boot state in ClearingKeys — retrying", "error", err)
			return nil
		}
		return fmt.Errorf("failed to read Secure Boot state post-reboot: %w", err)
	}
	if sbState.Mode != bmc.SecureBootModeSetup {
		log.V(1).Info("Waiting for SetupMode after key clear", "currentMode", sbState.Mode)
		return nil
	}

	// Keys cleared and SetupMode confirmed.
	keysClearedCond, err := utils.GetCondition(r.Conditions, sbc.Status.Conditions, constants.ConditionSBKeysCleared)
	if err != nil {
		return err
	}
	if err := r.Conditions.Update(keysClearedCond,
		conditionutils.UpdateStatus(metav1.ConditionTrue),
		conditionutils.UpdateReason(constants.ReasonSBKeysCleared),
		conditionutils.UpdateMessage("SetupMode confirmed — keys cleared"),
	); err != nil {
		return err
	}

	desired := sbc.Spec.DesiredState
	if desired == systemv1alpha1.SecureBootDesiredStateDisabled {
		if err := bmcClient.DisableBootOverride(ctx, server.Spec.SystemURI); err != nil {
			log.V(1).Info("Could not clear PXE override after disabling Secure Boot", "error", err)
		}
		if err := r.patchServerLabel(ctx, server, "false"); err != nil {
			return err
		}
		if err := r.patchCompletionCondition(ctx, sbc, server); err != nil {
			return err
		}
		if err := r.cleanupServerMaintenance(ctx, sbc); err != nil {
			return err
		}
		return r.updateStateWithCondition(ctx, sbc, systemv1alpha1.SecureBootConfigStateDisabled, keysClearedCond)
	}

	// Keep the ServerMaintenance alive so handleEnrolling reuses the same maintenance
	// window without an extra park/unpark cycle between clearing and enrollment.
	return r.updateStateWithCondition(ctx, sbc, systemv1alpha1.SecureBootConfigStateEnrolling, keysClearedCond)
}

func (r *SecureBootConfigReconciler) handleEnrolling(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	sbManager, err := r.getSecureBootManager(ctx, sbc, bmcClient)
	if err != nil {
		return err
	}

	active, err := r.ensureMaintenance(ctx, sbc, server)
	if err != nil {
		return err
	}
	if !active {
		return nil
	}

	if sbc.Status.RebootIssuedForState != systemv1alpha1.SecureBootConfigStateEnrolling {
		keySecret, err := r.getKeySecret(ctx, sbc)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return r.failWith(ctx, sbc, constants.ReasonSBEnrollFailed, fmt.Sprintf("key Secret not found: %v", err))
			}
			return err
		}

		if err := r.enrollKeys(ctx, sbc, server, sbManager, keySecret); err != nil {
			if isBMCBusy(err) {
				log.V(1).Info("BMC busy during key enrollment — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBEnrollFailed, fmt.Sprintf("key enrollment failed: %v", err))
		}

		log.V(1).Info("Keys enrolled — issuing reboot to commit")
		if err := r.rebootServer(ctx, server, bmcClient); err != nil {
			return fmt.Errorf("failed to reboot server post-enrollment: %w", err)
		}
		return r.markRebootIssued(ctx, sbc)
	}

	// Verify UserMode after reboot.
	sbState, err := sbManager.GetSecureBootState(ctx, server.Spec.SystemURI)
	if err != nil {
		if isBMCBusy(err) {
			log.V(1).Info("BMC busy reading Secure Boot state in Enrolling — retrying", "error", err)
			return nil
		}
		return fmt.Errorf("failed to read Secure Boot state post-enrollment: %w", err)
	}
	if sbState.Mode != bmc.SecureBootModeUser {
		log.V(1).Info("Waiting for UserMode after key enrollment", "currentMode", sbState.Mode)
		return nil
	}

	keySecret, err := r.getKeySecret(ctx, sbc)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return r.failWith(ctx, sbc, constants.ReasonSBEnrollFailed, fmt.Sprintf("key Secret not found: %v", err))
		}
		return err
	}

	keysEnrolledCond, err := utils.GetCondition(r.Conditions, sbc.Status.Conditions, constants.ConditionSBKeysEnrolled)
	if err != nil {
		return err
	}
	if err := r.Conditions.Update(keysEnrolledCond,
		conditionutils.UpdateStatus(metav1.ConditionTrue),
		conditionutils.UpdateReason(constants.ReasonSBKeysEnrolled),
		conditionutils.UpdateMessage("UserMode confirmed — keys enrolled"),
	); err != nil {
		return err
	}

	base := sbc.DeepCopy()
	sbc.Status.EnabledKeySecret = keySecret.ResourceVersion
	// Keep the ServerMaintenance alive so handleEnabling reuses the same maintenance
	// window without a park/unpark cycle between enrollment and enabling.
	sbc.Status.State = systemv1alpha1.SecureBootConfigStateEnrolled
	sbc.Status.RebootIssuedForState = ""
	sbc.Status.ObservedGeneration = sbc.Generation
	if err := r.Conditions.UpdateSlice(&sbc.Status.Conditions, keysEnrolledCond.Type,
		conditionutils.UpdateStatus(keysEnrolledCond.Status),
		conditionutils.UpdateReason(keysEnrolledCond.Reason),
		conditionutils.UpdateMessage(keysEnrolledCond.Message),
	); err != nil {
		return err
	}
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

func (r *SecureBootConfigReconciler) handleEnabling(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	sbManager, err := r.getSecureBootManager(ctx, sbc, bmcClient)
	if err != nil {
		return err
	}

	active, err := r.ensureMaintenance(ctx, sbc, server)
	if err != nil {
		return err
	}
	if !active {
		return nil
	}

	if sbc.Status.RebootIssuedForState != systemv1alpha1.SecureBootConfigStateEnabling {
		if err := sbManager.SetSecureBootEnabled(ctx, server.Spec.SystemURI, true); err != nil {
			if isBMCBusy(err) {
				// If we have been blocked by POST for longer than PostStuckTimeout,
				// the server has no boot target and will stay in POST indefinitely.
				// Issue a ForceOff to let iLO exit POST so the next reconcile can
				// succeed.
				if r.postStuck(sbc) {
					log.V(1).Info("Server stuck in POST — issuing ForceOff to unblock iLO", "error", err)
					if offErr := bmcClient.ForcePowerOff(ctx, server.Spec.SystemURI); offErr != nil {
						log.V(1).Info("ForceOff failed, will retry next reconcile", "error", offErr)
					}
				}
				log.V(1).Info("BMC busy (503) during SetSecureBootEnabled(true) — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBEnrollFailed, fmt.Sprintf("failed to enable Secure Boot: %v", err))
		}
		log.V(1).Info("Secure Boot enabled — issuing reboot")
		if err := r.rebootServer(ctx, server, bmcClient); err != nil {
			return fmt.Errorf("failed to reboot server to activate Secure Boot: %w", err)
		}
		return r.markRebootIssued(ctx, sbc)
	}

	// Verify Secure Boot is active after the reboot. Poll the SecureBoot state
	// directly rather than waiting for PowerState=On: on Dell the enable commits
	// during POST, and a host with no bootable OS (or one that panics) never
	// sustains a powered-on state, so gating on power-on would wait forever.
	sbState, err := sbManager.GetSecureBootState(ctx, server.Spec.SystemURI)
	if err != nil {
		if isBMCBusy(err) {
			log.V(1).Info("BMC busy reading Secure Boot state in Enabling — retrying", "error", err)
			return nil
		}
		return fmt.Errorf("failed to read Secure Boot state after enabling: %w", err)
	}
	if !sbState.Enabled {
		log.V(1).Info("Waiting for Secure Boot to be enabled after reboot", "mode", sbState.Mode)
		return nil
	}

	sbEnabledCond, err := utils.GetCondition(r.Conditions, sbc.Status.Conditions, constants.ConditionSBEnabled)
	if err != nil {
		return err
	}
	if err := r.Conditions.Update(sbEnabledCond,
		conditionutils.UpdateStatus(metav1.ConditionTrue),
		conditionutils.UpdateReason(constants.ReasonSBEnabled),
		conditionutils.UpdateMessage("Secure Boot active (CurrentBoot=true)"),
	); err != nil {
		return err
	}

	if err := bmcClient.DisableBootOverride(ctx, server.Spec.SystemURI); err != nil {
		log.V(1).Info("Could not clear PXE override after enabling Secure Boot", "error", err)
	}
	if err := r.patchServerLabel(ctx, server, "true"); err != nil {
		return err
	}
	if err := r.patchCompletionCondition(ctx, sbc, server); err != nil {
		return err
	}

	// Transition to Enabled BEFORE cleaning up the SM. If we deleted the SM first,
	// the Owns watch would trigger a new reconcile while the SBC is still in Enabling
	// state, causing ensureMaintenance to recreate the SM. By moving to Enabled first,
	// any reconcile triggered by SM deletion lands in handleEnabled, which never creates an SM.
	base := sbc.DeepCopy()
	sbc.Status.State = systemv1alpha1.SecureBootConfigStateEnabled
	sbc.Status.ObservedGeneration = sbc.Generation
	now := metav1.Now()
	sbc.Status.LastEnabledTime = &now
	if err := r.Conditions.UpdateSlice(&sbc.Status.Conditions, sbEnabledCond.Type,
		conditionutils.UpdateStatus(sbEnabledCond.Status),
		conditionutils.UpdateReason(sbEnabledCond.Reason),
		conditionutils.UpdateMessage(sbEnabledCond.Message),
	); err != nil {
		return err
	}
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

func (r *SecureBootConfigReconciler) handleEnabled(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	// Clean up any SM left over from the Enabling→Enabled transition. This covers
	// the case where the state patch in handleEnabling completed but the SM delete
	// was not issued yet (or failed and needs a retry).
	if sbc.Status.ServerMaintenanceRef != nil {
		if err := r.cleanupServerMaintenance(ctx, sbc); err != nil {
			return err
		}
	}

	sbManager, err := r.getSecureBootManager(ctx, sbc, bmcClient)
	if err != nil {
		return err
	}

	if sbc.Spec.DesiredState != "" && sbc.Spec.DesiredState != systemv1alpha1.SecureBootDesiredStateEnabled {
		log.V(1).Info("DesiredState changed away from Enabled — transitioning to Pending", "desiredState", sbc.Spec.DesiredState)
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStatePending, nil)
	}

	// Check for re-enroll annotation.
	if sbc.Annotations[constants.OperationAnnotation] == operationReEnroll {
		base := sbc.DeepCopy()
		delete(sbc.Annotations, constants.OperationAnnotation)
		if err := r.Patch(ctx, sbc, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("failed to remove re-enroll annotation: %w", err)
		}
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStateClearingKeys, nil)
	}

	// Periodic drift check.
	sbState, err := sbManager.GetSecureBootState(ctx, server.Spec.SystemURI)
	if err != nil {
		log.V(1).Info("Transient error reading Secure Boot state, will retry", "error", err)
		return nil
	}

	keySecret, err := r.getKeySecret(ctx, sbc)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return r.failWith(ctx, sbc, constants.ReasonSBDriftSecret, fmt.Sprintf("key Secret not found: %v", err))
		}
		return err
	}

	hardwareDrift := !sbState.Enabled
	secretDrift := sbc.Status.EnabledKeySecret != "" && sbc.Status.EnabledKeySecret != keySecret.ResourceVersion

	if hardwareDrift || secretDrift {
		reason := constants.ReasonSBDriftHardware
		msg := "Secure Boot disabled on hardware since last enrollment"
		if secretDrift {
			reason = constants.ReasonSBDriftSecret
			msg = "Key Secret updated since last enrollment"
		}
		log.V(1).Info("Secure Boot drift detected", "reason", reason)
		driftCond, err := utils.GetCondition(r.Conditions, sbc.Status.Conditions, constants.ConditionSBDrifted)
		if err != nil {
			return err
		}
		if err := r.Conditions.Update(driftCond,
			conditionutils.UpdateStatus(metav1.ConditionTrue),
			conditionutils.UpdateReason(reason),
			conditionutils.UpdateMessage(msg),
		); err != nil {
			return err
		}
		return r.updateStateWithCondition(ctx, sbc, systemv1alpha1.SecureBootConfigStatePending, driftCond)
	}

	return nil // no drift — steady state, requeue by ResyncInterval
}

func (r *SecureBootConfigReconciler) handleDisabled(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) error {
	if sbc.Spec.DesiredState != systemv1alpha1.SecureBootDesiredStateDisabled {
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStatePending, nil)
	}
	return nil
}

// handleResettingKeys drives DesiredState=FactoryDefault: it issues
// ResetAllKeysToDefault, reboots, and confirms the factory keys are restored with
// Secure Boot disabled. Unlike ClearingKeys it does NOT ensure a custom key
// policy — the factory reset deliberately returns the server to its shipped
// (Standard) policy and vendor keys.
func (r *SecureBootConfigReconciler) handleResettingKeys(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	log := ctrl.LoggerFrom(ctx)

	sbManager, err := r.getSecureBootManager(ctx, sbc, bmcClient)
	if err != nil {
		return err
	}

	active, err := r.ensureMaintenance(ctx, sbc, server)
	if err != nil {
		return err
	}
	if !active {
		return nil // waiting for maintenance window
	}

	if sbc.Status.RebootIssuedForState != systemv1alpha1.SecureBootConfigStateResettingKeys {
		if err := sbManager.ResetSecureBootKeys(ctx, server.Spec.SystemURI, bmc.SecureBootResetResetAllKeysToDefault); err != nil {
			if isBMCBusy(err) {
				log.V(1).Info("BMC busy during ResetSecureBootKeys in ResettingKeys — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBFactoryResetFailed, fmt.Sprintf("failed to reset keys to factory default: %v", err))
		}
		// ResetAllKeysToDefault restores the factory keys but, on Dell, leaves
		// Secure Boot enabled against them. FactoryDefault must end with Secure Boot
		// OFF (so a Microsoft-signed firmware update cannot be blocked), so disable
		// it explicitly in the same staged batch.
		if err := sbManager.SetSecureBootEnabled(ctx, server.Spec.SystemURI, false); err != nil {
			if isBMCBusy(err) {
				log.V(1).Info("BMC busy (503) during SetSecureBootEnabled(false) in ResettingKeys — retrying", "error", err)
				return nil
			}
			return r.failWith(ctx, sbc, constants.ReasonSBFactoryResetFailed, fmt.Sprintf("failed to disable Secure Boot: %v", err))
		}
		if err := bmcClient.SetBootOverrideContinuous(ctx, server.Spec.SystemURI); err != nil {
			log.V(1).Info("Could not set continuous PXE override; rebooting without it", "error", err)
		}
		log.V(1).Info("Keys reset to factory default and Secure Boot disabled — issuing reboot to commit")
		if err := r.rebootServer(ctx, server, bmcClient); err != nil {
			return fmt.Errorf("failed to reboot server: %w", err)
		}
		return r.markRebootIssued(ctx, sbc)
	}

	// Verify Secure Boot is off after the reset reboot. On the tested Dell,
	// ResetAllKeysToDefault leaves SecureBootEnable=false with the factory keys
	// restored, so the enable flag is the reliable commit signal.
	sbState, err := sbManager.GetSecureBootState(ctx, server.Spec.SystemURI)
	if err != nil {
		if isBMCBusy(err) {
			log.V(1).Info("BMC busy reading Secure Boot state in ResettingKeys — retrying", "error", err)
			return nil
		}
		return fmt.Errorf("failed to read Secure Boot state post-reboot: %w", err)
	}
	if sbState.Enabled {
		log.V(1).Info("Waiting for Secure Boot off after factory reset", "enabled", sbState.Enabled)
		return nil
	}

	factoryCond, err := utils.GetCondition(r.Conditions, sbc.Status.Conditions, constants.ConditionSBFactoryDefault)
	if err != nil {
		return err
	}
	if err := r.Conditions.Update(factoryCond,
		conditionutils.UpdateStatus(metav1.ConditionTrue),
		conditionutils.UpdateReason(constants.ReasonSBFactoryReset),
		conditionutils.UpdateMessage("Factory keys restored — Secure Boot off"),
	); err != nil {
		return err
	}

	if err := bmcClient.DisableBootOverride(ctx, server.Spec.SystemURI); err != nil {
		log.V(1).Info("Could not clear PXE override after factory reset", "error", err)
	}
	if err := r.patchServerLabel(ctx, server, "false"); err != nil {
		return err
	}
	if err := r.patchCompletionCondition(ctx, sbc, server); err != nil {
		return err
	}
	if err := r.cleanupServerMaintenance(ctx, sbc); err != nil {
		return err
	}
	return r.updateStateWithCondition(ctx, sbc, systemv1alpha1.SecureBootConfigStateFactoryDefault, factoryCond)
}

// handleFactoryDefault is the terminal steady state for DesiredState=FactoryDefault.
// A spec change to Enabled or Disabled re-evaluates from Pending.
func (r *SecureBootConfigReconciler) handleFactoryDefault(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) error {
	if sbc.Spec.DesiredState != systemv1alpha1.SecureBootDesiredStateFactoryDefault {
		return r.updateState(ctx, sbc, systemv1alpha1.SecureBootConfigStatePending, nil)
	}
	return nil
}

func (r *SecureBootConfigReconciler) handleFailed(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) error {
	if utils.ShouldRetryReconciliation(sbc) {
		// Patch metadata (annotation removal) first, then status separately so
		// each patch is diffed against the correct base.
		metaBase := sbc.DeepCopy()
		delete(sbc.Annotations, constants.OperationAnnotation)
		if err := r.Patch(ctx, sbc, client.MergeFrom(metaBase)); err != nil {
			return fmt.Errorf("failed to remove retry annotation: %w", err)
		}
		statusBase := sbc.DeepCopy()
		sbc.Status.State = systemv1alpha1.SecureBootConfigStatePending
		sbc.Status.ObservedGeneration = sbc.Generation
		sbc.Status.Conditions = nil
		sbc.Status.FailedAttempts = 0
		if err := r.Status().Patch(ctx, sbc, client.MergeFrom(statusBase)); err != nil {
			return fmt.Errorf("failed to reset SecureBootConfig status for retry: %w", err)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Key enrollment helpers
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigReconciler) enrollKeys(ctx context.Context, _ *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server, sbManager bmc.SecureBootManager, secret *corev1.Secret) error {
	// Enroll in this order: db entries first, then KEK, then PK last
	// (enrolling PK with our key locks the store into UserMode).
	for key, val := range secret.Data {
		data := string(val)
		switch {
		case key == "db.crt" || (strings.HasPrefix(key, "db.crt.") && key != "db.crt"):
			if err := sbManager.EnrollCertificate(ctx, server.Spec.SystemURI, "db", data); err != nil {
				return fmt.Errorf("enrolling %s: %w", key, err)
			}
		case key == "db.sha256" || strings.HasPrefix(key, "db.sha256."):
			if err := sbManager.EnrollHash(ctx, server.Spec.SystemURI, "db", strings.TrimSpace(data)); err != nil {
				return fmt.Errorf("enrolling %s: %w", key, err)
			}
		case key == "dbx.sha256" || strings.HasPrefix(key, "dbx.sha256."):
			if err := sbManager.EnrollHash(ctx, server.Spec.SystemURI, "dbx", strings.TrimSpace(data)); err != nil {
				return fmt.Errorf("enrolling %s: %w", key, err)
			}
		}
	}
	if kek, ok := secret.Data["kek.crt"]; ok {
		if err := sbManager.EnrollCertificate(ctx, server.Spec.SystemURI, "KEK", string(kek)); err != nil {
			return fmt.Errorf("enrolling kek.crt: %w", err)
		}
	}
	if pk, ok := secret.Data["pk.crt"]; ok {
		if err := sbManager.EnrollCertificate(ctx, server.Spec.SystemURI, "PK", string(pk)); err != nil {
			return fmt.Errorf("enrolling pk.crt: %w", err)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Maintenance window helpers
// ──────────────────────────────────────────────────────────────────────────────

// ensureMaintenance creates a ServerMaintenance if none exists, then returns
// true when the server is actively in the maintenance window.
func (r *SecureBootConfigReconciler) ensureMaintenance(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server) (bool, error) {
	log := ctrl.LoggerFrom(ctx)

	if sbc.Status.ServerMaintenanceRef == nil {
		sm := &maintenancev1alpha1.ServerMaintenance{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: sbc.Namespace,
				Name:      sbc.Name,
			},
		}
		_, err := controllerutil.CreateOrPatch(ctx, r.Client, sm, func() error {
			sm.Spec.Policy = sbc.Spec.ServerMaintenancePolicy
			if sm.Spec.Policy == "" {
				sm.Spec.Policy = maintenancev1alpha1.ServerMaintenancePolicyEnforced
			}
			sm.Spec.ServerRef = &corev1.LocalObjectReference{Name: server.Name}
			return controllerutil.SetControllerReference(sbc, sm, r.Scheme)
		})
		if err != nil {
			return false, fmt.Errorf("failed to create ServerMaintenance: %w", err)
		}
		base := sbc.DeepCopy()
		sbc.Status.ServerMaintenanceRef = &metalv1alpha1.ObjectReference{
			Namespace: sm.Namespace,
			Name:      sm.Name,
		}
		if err := r.Status().Patch(ctx, sbc, client.MergeFrom(base)); err != nil {
			return false, err
		}
		return false, nil
	}

	active, err := utils.IsAnyServerMaintenanceActive(ctx, r.Client, []metalv1alpha1.ObjectReference{*sbc.Status.ServerMaintenanceRef})
	if err != nil {
		return false, fmt.Errorf("failed to check maintenance state: %w", err)
	}
	if !active {
		log.V(1).Info("Waiting for maintenance window", "ServerMaintenance", sbc.Status.ServerMaintenanceRef.Name)
		return false, nil
	}
	return true, nil
}

func (r *SecureBootConfigReconciler) cleanupServerMaintenance(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) error {
	if sbc.Status.ServerMaintenanceRef == nil {
		return nil
	}
	sm := &maintenancev1alpha1.ServerMaintenance{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: sbc.Status.ServerMaintenanceRef.Namespace,
		Name:      sbc.Status.ServerMaintenanceRef.Name,
	}, sm)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get ServerMaintenance for cleanup: %w", err)
	}
	if err == nil && metav1.IsControlledBy(sm, sbc) {
		if err := r.Delete(ctx, sm); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ServerMaintenance: %w", err)
		}
	} else if err != nil {
		// Not found — SM is already gone; clear the ref.
		// If it exists but is not ours, leave it alone and do not clear the ref.
		base := sbc.DeepCopy()
		sbc.Status.ServerMaintenanceRef = nil
		return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
	} else {
		// SM exists but is not owned by this SBC — leave both the SM and the ref intact.
		return nil
	}
	base := sbc.DeepCopy()
	sbc.Status.ServerMaintenanceRef = nil
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

// ──────────────────────────────────────────────────────────────────────────────
// Status / condition helpers
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigReconciler) updateState(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, state systemv1alpha1.SecureBootConfigState, condition *metav1.Condition) error { //nolint:unparam
	base := sbc.DeepCopy()
	sbc.Status.State = state
	sbc.Status.ObservedGeneration = sbc.Generation
	sbc.Status.RebootIssuedForState = ""
	if condition == nil {
		sbc.Status.Conditions = nil
	}
	now := metav1.Now()
	sbc.Status.LastProgressTime = &now
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

func (r *SecureBootConfigReconciler) updateStateWithCondition(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, state systemv1alpha1.SecureBootConfigState, condition *metav1.Condition) error {
	base := sbc.DeepCopy()
	sbc.Status.State = state
	sbc.Status.ObservedGeneration = sbc.Generation
	sbc.Status.RebootIssuedForState = ""
	now := metav1.Now()
	sbc.Status.LastProgressTime = &now
	if condition != nil {
		if err := r.Conditions.UpdateSlice(&sbc.Status.Conditions, condition.Type,
			conditionutils.UpdateStatus(condition.Status),
			conditionutils.UpdateReason(condition.Reason),
			conditionutils.UpdateMessage(condition.Message),
		); err != nil {
			return err
		}
	}
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

// rebootServer cycles the host to commit staged BIOS/Secure Boot changes.
// Uses ForceRestart (not GracefulRestart) so it works even with no OS, and
// powers on instead of restarting when the host is currently off.
func (r *SecureBootConfigReconciler) rebootServer(ctx context.Context, server *metalv1alpha1.Server, bmcClient bmc.BMC) error {
	on, err := utils.IsServerInPowerState(ctx, bmcClient, server, metalv1alpha1.ServerOnPowerState)
	if err != nil {
		return fmt.Errorf("failed to check server power state: %w", err)
	}
	resetType := schemas.ForceRestartResetType
	if !on {
		resetType = schemas.OnResetType
	}
	return bmcClient.Reset(ctx, server.Spec.SystemURI, resetType)
}

// markRebootIssued persists that a BMC reboot was issued for the current state.
// On the next reconcile the handler checks RebootIssuedForState == current state
// to enter the post-reboot verification path.
func (r *SecureBootConfigReconciler) markRebootIssued(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) error {
	base := sbc.DeepCopy()
	sbc.Status.RebootIssuedForState = sbc.Status.State
	sbc.Status.ObservedGeneration = sbc.Generation
	now := metav1.Now()
	sbc.Status.LastProgressTime = &now
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

func (r *SecureBootConfigReconciler) failWith(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, reason, msg string) error {
	base := sbc.DeepCopy()
	sbc.Status.State = systemv1alpha1.SecureBootConfigStateFailed
	sbc.Status.ObservedGeneration = sbc.Generation
	sbc.Status.FailedAttempts++
	if err := r.Conditions.UpdateSlice(&sbc.Status.Conditions, "Failed",
		conditionutils.UpdateStatus(metav1.ConditionTrue),
		conditionutils.UpdateReason(reason),
		conditionutils.UpdateMessage(msg),
	); err != nil {
		return err
	}
	return r.Status().Patch(ctx, sbc, client.MergeFrom(base))
}

func (r *SecureBootConfigReconciler) patchServerLabel(ctx context.Context, server *metalv1alpha1.Server, value string) error {
	base := server.DeepCopy()
	if server.Labels == nil {
		server.Labels = make(map[string]string)
	}
	server.Labels[labelSecureBootEnabled] = value
	return r.Patch(ctx, server, client.MergeFrom(base))
}

func (r *SecureBootConfigReconciler) patchCompletionCondition(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server) error {
	if sbc.Spec.CompletionConditionType == "" {
		return nil
	}
	base := server.DeepCopy()
	cond := metav1.Condition{
		Type:               sbc.Spec.CompletionConditionType,
		Status:             metav1.ConditionTrue,
		Reason:             "SecureBootConfigCompleted",
		Message:            fmt.Sprintf("SecureBootConfig %s/%s reached terminal state", sbc.Namespace, sbc.Name),
		LastTransitionTime: metav1.Now(),
	}
	found := false
	for i, c := range server.Status.Conditions {
		if c.Type == cond.Type {
			server.Status.Conditions[i] = cond
			found = true
			break
		}
	}
	if !found {
		server.Status.Conditions = append(server.Status.Conditions, cond)
	}
	return r.Status().Patch(ctx, server, client.MergeFrom(base))
}

// ──────────────────────────────────────────────────────────────────────────────
// BMC client helpers
// ──────────────────────────────────────────────────────────────────────────────

// postStuck returns true when the SBC has been in the pre-reboot Enabling phase
// for longer than PostStuckTimeout, indicating the server is stuck in POST.
func (r *SecureBootConfigReconciler) postStuck(sbc *systemv1alpha1.SecureBootConfig) bool {
	if r.PostStuckTimeout <= 0 || sbc.Status.LastProgressTime == nil {
		return false
	}
	return time.Since(sbc.Status.LastProgressTime.Time) > r.PostStuckTimeout
}

// getBMCClient returns a BMC client. Returns (nil, nil, false, nil) when the BMC
// is unavailable (caller should requeue). Returns (nil, nil, false, err) on
// unrecoverable error.
func (r *SecureBootConfigReconciler) getBMCClient(ctx context.Context, _ *systemv1alpha1.SecureBootConfig, server *metalv1alpha1.Server) (bmc.BMC, func(), bool, error) {
	log := ctrl.LoggerFrom(ctx)
	bmcClient, err := bmcutils.GetBMCClientForServer(ctx, r.Client, server, r.DefaultProtocol, r.SkipCertValidation, r.BMCOptions)
	if err != nil {
		if errors.As(err, &bmcutils.BMCUnAvailableError{}) {
			log.V(1).Info("BMC unavailable, requeueing", "server", server.Name)
			return nil, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("failed to get BMC client: %w", err)
	}
	return bmcClient, bmcClient.Logout, true, nil
}

// getSecureBootManager asserts that the BMC client implements SecureBootManager,
// failing the SBC with a permanent error if the hardware does not support it.
func (r *SecureBootConfigReconciler) getSecureBootManager(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig, bmcClient bmc.BMC) (bmc.SecureBootManager, error) {
	sbManager, ok := bmcClient.(bmc.SecureBootManager)
	if !ok {
		return nil, r.failWith(ctx, sbc, constants.ReasonSBNotSupported, "BMC client does not implement SecureBootManager")
	}
	return sbManager, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Secret helper
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigReconciler) getKeySecret(ctx context.Context, sbc *systemv1alpha1.SecureBootConfig) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: sbc.Namespace,
		Name:      sbc.Spec.KeySecretRef.Name,
	}, secret); err != nil {
		return nil, fmt.Errorf("failed to get key Secret %s: %w", sbc.Spec.KeySecretRef.Name, err)
	}
	return secret, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// SetupWithManager
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&systemv1alpha1.SecureBootConfig{}).
		Owns(&maintenancev1alpha1.ServerMaintenance{}).
		Watches(
			&metalv1alpha1.Server{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueForServer),
		).
		Complete(r)
}

func (r *SecureBootConfigReconciler) enqueueForServer(ctx context.Context, obj client.Object) []ctrl.Request {
	sbcList := &systemv1alpha1.SecureBootConfigList{}
	if err := r.List(ctx, sbcList, client.MatchingFields{constants.ServerRefField: obj.GetName()}); err != nil {
		return nil
	}
	reqs := make([]ctrl.Request, 0, len(sbcList.Items))
	for _, sbc := range sbcList.Items {
		reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{
			Namespace: sbc.Namespace,
			Name:      sbc.Name,
		}})
	}
	return reqs
}

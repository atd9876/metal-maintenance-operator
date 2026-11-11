// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ironcore-dev/controller-utils/clientutils"
	systemv1alpha1 "github.com/ironcore-dev/metal-maintenance-operator/api/system/v1alpha1"
	constants "github.com/ironcore-dev/metal-maintenance-operator/internal/constants"
	utils "github.com/ironcore-dev/metal-maintenance-operator/internal/utils"
	metalv1alpha1 "github.com/ironcore-dev/metal-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	secureBootConfigSetFinalizer = "system.metal.ironcore.dev/securebootconfigset"
)

// SecureBootConfigSetReconciler reconciles a SecureBootConfigSet object.
type SecureBootConfigSetReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	ResyncInterval time.Duration
}

// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigsets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigsets/finalizers,verbs=update
// +kubebuilder:rbac:groups=system.metal.ironcore.dev,resources=securebootconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=servers,verbs=get;list;watch

func (r *SecureBootConfigSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	set := &systemv1alpha1.SecureBootConfigSet{}
	if err := r.Get(ctx, req.NamespacedName, set); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return r.reconcileExists(ctx, set)
}

func (r *SecureBootConfigSetReconciler) reconcileExists(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) (ctrl.Result, error) {
	if !set.DeletionTimestamp.IsZero() {
		return r.delete(ctx, set)
	}
	return r.reconcile(ctx, set)
}

func (r *SecureBootConfigSetReconciler) delete(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	if !controllerutil.ContainsFinalizer(set, secureBootConfigSetFinalizer) {
		return ctrl.Result{}, nil
	}

	if err := r.handleIgnorePropagation(ctx, set); err != nil {
		return ctrl.Result{}, err
	}

	owned, err := r.getOwnedConfigs(ctx, set)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Only delete children that are not inside an active maintenance window.
	deletable := map[string]struct{}{}
	for _, sbc := range owned.Items {
		if sbc.Status.ServerMaintenanceRef == nil {
			deletable[sbc.Name] = struct{}{}
			continue
		}
		active, err := utils.IsAnyServerMaintenanceActive(ctx, r.Client, []metalv1alpha1.ObjectReference{*sbc.Status.ServerMaintenanceRef})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to check maintenance state for SecureBootConfig %s: %w", sbc.Name, err)
		}
		if !active {
			deletable[sbc.Name] = struct{}{}
		}
	}

	if len(owned.Items) != len(deletable) {
		status := r.computeStatus(owned)
		if err := r.patchStatus(ctx, set, status); err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("Waiting for active SecureBootConfigs to finish before deletion")
		return ctrl.Result{}, nil
	}

	if modified, err := clientutils.PatchEnsureNoFinalizer(ctx, r.Client, set, secureBootConfigSetFinalizer); err != nil || modified {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *SecureBootConfigSetReconciler) reconcile(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	log.V(1).Info("Reconciling SecureBootConfigSet")

	if err := r.handleIgnorePropagation(ctx, set); err != nil {
		return ctrl.Result{}, err
	}

	if utils.ShouldIgnoreReconciliation(set) {
		log.V(1).Info("Skipped SecureBootConfigSet reconciliation")
		return ctrl.Result{}, nil
	}

	if modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, set, secureBootConfigSetFinalizer); err != nil || modified {
		return ctrl.Result{}, err
	}

	servers, err := r.getServersBySelector(ctx, set)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list servers by selector: %w", err)
	}

	owned, err := r.getOwnedConfigs(ctx, set)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.createMissing(ctx, set, servers, owned); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create missing SecureBootConfigs: %w", err)
	}

	// Refresh after creation.
	owned, err = r.getOwnedConfigs(ctx, set)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.deleteOrphans(ctx, servers, owned); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to delete orphaned SecureBootConfigs: %w", err)
	}

	pendingPatch, err := r.patchFromTemplate(ctx, set, owned)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to patch SecureBootConfigs from template: %w", err)
	}

	if err := r.handleRetryPropagation(ctx, set); err != nil {
		return ctrl.Result{}, err
	}

	status := r.computeStatus(owned)
	status.FullyLabeledServers = int32(len(servers.Items))
	if err := r.patchStatus(ctx, set, status); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to patch SecureBootConfigSet status: %w", err)
	}

	if status.FullyLabeledServers != status.AvailableSecureBootConfigs || pendingPatch {
		return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
	}
	return ctrl.Result{}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Fan-out helpers
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigSetReconciler) createMissing(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet, servers *metalv1alpha1.ServerList, owned *systemv1alpha1.SecureBootConfigList) error {
	log := ctrl.LoggerFrom(ctx)
	existing := make(map[string]struct{}, len(owned.Items))
	for _, sbc := range owned.Items {
		if sbc.Spec.ServerRef != nil {
			existing[sbc.Spec.ServerRef.Name] = struct{}{}
		}
	}

	var errs []error
	for _, server := range servers.Items {
		if _, ok := existing[server.Name]; ok {
			continue
		}
		// Guard against stale cache creating duplicates.
		checkList := &systemv1alpha1.SecureBootConfigList{}
		if err := r.List(ctx, checkList, client.MatchingFields{constants.ServerRefField: server.Name}); err != nil {
			errs = append(errs, err)
			continue
		}
		if len(checkList.Items) > 0 {
			log.V(1).Info("SecureBootConfig already exists for server", "server", server.Name)
			continue
		}

		childName := utils.VersionSetChildName(set.Name, server.Name)
		child := &systemv1alpha1.SecureBootConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      childName,
				Namespace: set.Namespace,
			},
		}
		opResult, err := controllerutil.CreateOrPatch(ctx, r.Client, child, func() error {
			r.applyTemplate(set, server.Name, child)
			return controllerutil.SetControllerReference(set, child, r.Scheme)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create SecureBootConfig for server %s: %w", server.Name, err))
			continue
		}
		log.V(1).Info("Created SecureBootConfig", "name", child.Name, "server", server.Name, "operation", opResult)
	}
	return errors.Join(errs...)
}

func (r *SecureBootConfigSetReconciler) deleteOrphans(ctx context.Context, servers *metalv1alpha1.ServerList, owned *systemv1alpha1.SecureBootConfigList) error {
	log := ctrl.LoggerFrom(ctx)
	serverMap := make(map[string]struct{}, len(servers.Items))
	for _, s := range servers.Items {
		serverMap[s.Name] = struct{}{}
	}

	var errs []error
	for _, sbc := range owned.Items {
		if sbc.Spec.ServerRef == nil {
			continue
		}
		if _, ok := serverMap[sbc.Spec.ServerRef.Name]; ok {
			continue
		}
		// Don't delete if inside an active maintenance window.
		if sbc.Status.ServerMaintenanceRef != nil {
			active, err := utils.IsAnyServerMaintenanceActive(ctx, r.Client, []metalv1alpha1.ObjectReference{*sbc.Status.ServerMaintenanceRef})
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if active {
				log.V(1).Info("Waiting for maintenance to finish before deleting orphan", "SecureBootConfig", sbc.Name)
				continue
			}
		}
		if err := r.Delete(ctx, &sbc); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *SecureBootConfigSetReconciler) patchFromTemplate(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet, owned *systemv1alpha1.SecureBootConfigList) (bool, error) {
	log := ctrl.LoggerFrom(ctx)
	var pendingPatch bool
	var errs []error
	for _, sbc := range owned.Items {
		// Don't patch while actively progressing through states.
		switch sbc.Status.State {
		case systemv1alpha1.SecureBootConfigStateClearingKeys,
			systemv1alpha1.SecureBootConfigStateEnrolling,
			systemv1alpha1.SecureBootConfigStateEnabling:
			pendingPatch = true
			continue
		}
		opResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &sbc, func() error {
			if sbc.Spec.ServerRef != nil {
				r.applyTemplate(set, sbc.Spec.ServerRef.Name, &sbc)
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if opResult != controllerutil.OperationResultNone {
			log.V(1).Info("Patched SecureBootConfig from template", "name", sbc.Name, "operation", opResult)
		}
	}
	return pendingPatch, errors.Join(errs...)
}

func (r *SecureBootConfigSetReconciler) applyTemplate(set *systemv1alpha1.SecureBootConfigSet, serverName string, sbc *systemv1alpha1.SecureBootConfig) {
	tmpl := &set.Spec.SecureBootConfigTemplate
	sbc.Spec.ServerRef = &corev1.LocalObjectReference{Name: serverName}
	sbc.Spec.KeySecretRef = corev1.LocalObjectReference{Name: tmpl.KeySecretRef.Name}
	sbc.Spec.DesiredState = tmpl.DesiredState
	sbc.Spec.ServerMaintenancePolicy = tmpl.ServerMaintenancePolicy
	sbc.Spec.RetryPolicy = tmpl.RetryPolicy
	sbc.Spec.ProgressDeadlineSeconds = tmpl.ProgressDeadlineSeconds
}

// ──────────────────────────────────────────────────────────────────────────────
// Status / annotation helpers
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigSetReconciler) computeStatus(owned *systemv1alpha1.SecureBootConfigList) *systemv1alpha1.SecureBootConfigSetStatus {
	s := &systemv1alpha1.SecureBootConfigSetStatus{
		AvailableSecureBootConfigs: int32(len(owned.Items)),
	}
	for _, sbc := range owned.Items {
		switch sbc.Status.State {
		case systemv1alpha1.SecureBootConfigStateEnabled, systemv1alpha1.SecureBootConfigStateDisabled:
			s.CompletedSecureBootConfigs++
		case systemv1alpha1.SecureBootConfigStateFailed:
			s.FailedSecureBootConfigs++
		case systemv1alpha1.SecureBootConfigStateClearingKeys,
			systemv1alpha1.SecureBootConfigStateEnrolling,
			systemv1alpha1.SecureBootConfigStateEnrolled,
			systemv1alpha1.SecureBootConfigStateEnabling:
			s.InProgressSecureBootConfigs++
		default:
			s.PendingSecureBootConfigs++
		}
	}
	return s
}

func (r *SecureBootConfigSetReconciler) patchStatus(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet, status *systemv1alpha1.SecureBootConfigSetStatus) error {
	base := set.DeepCopy()
	set.Status = *status
	return r.Status().Patch(ctx, set, client.MergeFrom(base))
}

func (r *SecureBootConfigSetReconciler) handleIgnorePropagation(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) error {
	owned, err := r.getOwnedConfigs(ctx, set)
	if err != nil {
		return err
	}
	if len(owned.Items) == 0 {
		return nil
	}
	return utils.HandleIgnoreAnnotationPropagation(ctx, r.Client, set, owned)
}

func (r *SecureBootConfigSetReconciler) handleRetryPropagation(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) error {
	owned, err := r.getOwnedConfigs(ctx, set)
	if err != nil {
		return err
	}
	if len(owned.Items) == 0 {
		return nil
	}
	return utils.HandleRetryAnnotationPropagation(ctx, r.Client, set, owned)
}

func (r *SecureBootConfigSetReconciler) getOwnedConfigs(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) (*systemv1alpha1.SecureBootConfigList, error) {
	list := &systemv1alpha1.SecureBootConfigList{}
	if err := clientutils.ListAndFilterControlledBy(ctx, r.Client, set, list); err != nil {
		return nil, fmt.Errorf("failed to list owned SecureBootConfigs: %w", err)
	}
	return list, nil
}

func (r *SecureBootConfigSetReconciler) getServersBySelector(ctx context.Context, set *systemv1alpha1.SecureBootConfigSet) (*metalv1alpha1.ServerList, error) {
	selector, err := metav1.LabelSelectorAsSelector(&set.Spec.ServerSelector)
	if err != nil {
		return nil, err
	}
	list := &metalv1alpha1.ServerList{}
	if err := r.List(ctx, list, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}
	return list, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// SetupWithManager
// ──────────────────────────────────────────────────────────────────────────────

func (r *SecureBootConfigSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&systemv1alpha1.SecureBootConfigSet{}).
		Owns(&systemv1alpha1.SecureBootConfig{}).
		Watches(
			&metalv1alpha1.Server{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueByServer),
			builder.WithPredicates(predicate.LabelChangedPredicate{}),
		).
		Complete(r)
}

func (r *SecureBootConfigSetReconciler) enqueueByServer(ctx context.Context, obj client.Object) []ctrl.Request {
	log := ctrl.LoggerFrom(ctx)
	server := obj.(*metalv1alpha1.Server)
	reqs := make(map[client.ObjectKey]bool)

	setList := &systemv1alpha1.SecureBootConfigSetList{}
	if err := r.List(ctx, setList); err == nil {
		for _, set := range setList.Items {
			sel, _ := metav1.LabelSelectorAsSelector(&set.Spec.ServerSelector)
			if sel.Matches(labels.Set(server.GetLabels())) {
				reqs[client.ObjectKeyFromObject(&set)] = true
			}
		}
	}

	sbcList := &systemv1alpha1.SecureBootConfigList{}
	if err := r.List(ctx, sbcList, client.MatchingFields{constants.ServerRefField: server.Name}); err != nil {
		log.Error(err, "Failed to list SecureBootConfigs for server", "server", server.Name)
	} else {
		for i := range sbcList.Items {
			owner := metav1.GetControllerOf(&sbcList.Items[i])
			if owner != nil && owner.Kind == "SecureBootConfigSet" {
				reqs[client.ObjectKey{Namespace: sbcList.Items[i].Namespace, Name: owner.Name}] = true
			}
		}
	}

	result := make([]ctrl.Request, 0, len(reqs))
	for k := range reqs {
		result = append(result, ctrl.Request{NamespacedName: k})
	}
	return result
}

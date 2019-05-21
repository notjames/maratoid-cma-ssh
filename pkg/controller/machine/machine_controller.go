/*
Copyright 2018 Samsung SDS.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package machine

import (
	"context"
	"time"

	"github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/common"
	clusterv1alpha1 "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/maas"
	"github.com/samsung-cnct/cma-ssh/pkg/util"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("CnctMachine-controller")

// AddWithActuator creates a new Machine Controller and adds it to the Manager
// with default RBAC. The Manager will set fields on the Controller and Start
// it when the Manager is Started.
func AddWithActuator(mgr manager.Manager, maasClient maas.Client) error {
	return add(mgr, newReconciler(mgr, maasClient))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, maasClient maas.Client) reconcile.Reconciler {
	return &ReconcileMachine{
		Client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		EventRecorder: mgr.GetRecorder("MachineController"),
		MAASClient:    maasClient,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("machine-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to Machine
	err = c.Watch(&source.Kind{Type: &clusterv1alpha1.CnctMachine{}}, &handler.EnqueueRequestForObject{})
	return err
}

var _ reconcile.Reconciler = &ReconcileMachine{}

// ReconcileMachine reconciles a Machine object
type ReconcileMachine struct {
	client.Client
	scheme *runtime.Scheme
	record.EventRecorder
	MAASClient maas.Client
}

// Reconcile reads that state of the cluster for a Machine object and makes changes based on the state read
// and what is in the Machine.Spec
// +kubebuilder:rbac:groups=cluster.cnct.sds.samsung.com,resources=cnctmachines;cnctclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
func (r *ReconcileMachine) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	log.Info("reconciling machine", "request", request)

	log.Info("get machine")
	var machine clusterv1alpha1.CnctMachine
	if err := r.Get(context.Background(), request.NamespacedName, &machine); err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, return.  Created objects are
			// automatically garbage collected.
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "could not get machine")
		return reconcile.Result{}, err
	}

	log.Info("get parent cluster of machine")
	// If this machine does not have an OwnerReference that matches the
	// cluster then we add it now. If the cluster has not been created yet
	// we will try again.
	var cluster clusterv1alpha1.CnctCluster
	var secret corev1.Secret
	{
		log.Info("listing clusters in machine namespace")
		var clusterList clusterv1alpha1.CnctClusterList
		if err := r.List(context.Background(), &client.ListOptions{Namespace: machine.Namespace}, &clusterList); err != nil {
			return reconcile.Result{}, err
		}
		if len(clusterList.Items) != 1 {
			log.Info("expected the number of clusters to be 1", "CnctClusterList", clusterList)
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
		cluster = clusterList.Items[0]
		log.Info("checking if machine has cluster owner reference")
		needsOwnerRef := true
		for _, ref := range machine.OwnerReferences {
			if ref.UID == cluster.UID {
				needsOwnerRef = false
				break
			}
		}
		if needsOwnerRef {
			log.Info("adding cluster owner reference to machine")
			isController := false
			blockOwnerDeletion := true
			gvk := clusterv1alpha1.SchemeGroupVersion.WithKind("CnctCluster")
			machineOwnerRef := metav1.OwnerReference{
				APIVersion:         gvk.GroupVersion().String(),
				Kind:               gvk.Kind,
				Name:               cluster.GetName(),
				UID:                cluster.GetUID(),
				BlockOwnerDeletion: &blockOwnerDeletion,
				Controller:         &isController,
			}
			machine.OwnerReferences = append(machine.OwnerReferences, machineOwnerRef)
			if err := r.Update(context.Background(), &machine); err != nil {
				return reconcile.Result{}, err
			}
		}
		log.Info("get the cluster secret")
		err := r.Client.Get(
			context.Background(),
			client.ObjectKey{
				Name:      "cluster-private-key",
				Namespace: cluster.Namespace,
			},
			&secret,
		)
		if err != nil {
			return reconcile.Result{}, errors.Wrap(err, "could not get cluster secret")
		}
		log.Info("checking if the machine has the secret owner reference")
		needsOwnerRef = true
		for _, ref := range machine.OwnerReferences {
			if ref.UID == secret.UID {
				needsOwnerRef = false
				break
			}
		}
		if needsOwnerRef {
			log.Info("adding secret owner reference to machine")
			isController := false
			blockOwnerDeletion := true
			gvk := secret.GroupVersionKind()
			machineOwnerRef := metav1.OwnerReference{
				APIVersion:         gvk.GroupVersion().String(),
				Kind:               gvk.Kind,
				Name:               secret.GetName(),
				UID:                secret.GetUID(),
				BlockOwnerDeletion: &blockOwnerDeletion,
				Controller:         &isController,
			}
			machine.OwnerReferences = append(machine.OwnerReferences, machineOwnerRef)
			if err := r.Update(context.Background(), &machine); err != nil {
				return reconcile.Result{}, err
			}
		}
	}

	log.Info("check if machine is being deleted")
	if !machine.DeletionTimestamp.IsZero() && machine.Status.Phase != common.DeletingMachinePhase {
		log.Info("machine is being deleted update phase to deleteing")
		machine.Status.Phase = common.DeletingMachinePhase
		err := r.Update(context.Background(), &machine)
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		} else if err != nil {
			log.Error(err, "this is broken")
			return reconcile.Result{}, err
		}
	}

	log.Info("handle machine phases")
	var err error
	switch machine.Status.Phase {
	case common.ProvisioningMachinePhase:
		err = r.handleWaitingForReady(&machine)
	case common.DeletingMachinePhase:
		err = r.handleDelete(&machine, &cluster)
	case common.ErrorMachinePhase, common.ReadyMachinePhase, common.UpgradingMachinePhase:
	default:
		err = create(r, r.MAASClient, &machine, &cluster, &secret)
	}
	if err != nil {
		switch e := errors.Cause(err).(type) {
		case *apierrors.StatusError:
			if apierrors.IsNotFound(e) {
				log.Info("during reconcile an object was not found", "machine", machine)
				return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
			} else {
				return reconcile.Result{}, err
			}
		case errNotReady:
			log.Error(err, "during reconcile an object was not ready", "machine", machine)
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		case errRelease:
			log.Error(err, "during reconcile we needed to release a machine", "machine", machine)
			r.MAASClient.Delete(context.Background(), &maas.DeleteRequest{"", e.systemID})
			return reconcile.Result{}, err
		default:
			return reconcile.Result{}, err
		}
	}
	log.Info("machine reconicle completed successfully")
	return reconcile.Result{}, nil
}

func (r *ReconcileMachine) handleUpgrade(
	machine *clusterv1alpha1.CnctMachine,
	cluster *clusterv1alpha1.CnctCluster,
) (reconcile.Result, error) {
	// if already upgrading, move on
	if machine.Status.Phase == common.UpgradingMachinePhase {
		return reconcile.Result{}, nil
	}

	// get cluster status to determine whether we should proceed,
	// i.e. if there is a create in progress, we wait for it to either
	// finish or error
	clusterName := util.GetClusterNameFromMachineOwnerRef(machine)
	cluster, err := getCluster(r.Client, machine.GetNamespace(), clusterName)
	if err != nil {
		return reconcile.Result{}, err
	}
	machineList, err := util.GetClusterMachineList(r.Client, cluster.GetName())
	if err != nil {
		log.Error(err, "could not list Machines for cluster", "cluster", cluster)
		return reconcile.Result{}, err
	}
	// if not ok to upgrade with error, return and do not requeue
	ok, err := util.IsReadyForUpgrade(machineList)
	if err != nil {
		log.Error(err, "cannot upgrade machine", "machine", machine)
		return reconcile.Result{}, nil
	}
	// if not ok to upgrade, try later
	if !ok {
		log.Info("Upgrade: Waiting for cluster to finish reconciling", "cluster", cluster)
		return reconcile.Result{Requeue: true}, nil
	}

	// update status to "upgrading"
	machine.Status.Phase = common.UpgradingMachinePhase
	err = r.updateStatus(machine, corev1.EventTypeNormal,
		common.ResourceStateChange, common.MessageResourceStateChange,
		machine.GetName(), common.UpgradingMachinePhase)
	if err != nil {
		log.Error(err, "could not update status of machine", "machine", machine)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileMachine) handleWaitingForReady(machine *clusterv1alpha1.CnctMachine) error {
	log.Info("figure out how to check if a machine is ready")
	return nil
}

func (r *ReconcileMachine) updateStatus(
	machineInstance *clusterv1alpha1.CnctMachine,
	eventType string,
	event common.ControllerEvents,
	eventMessage common.ControllerEvents,
	args ...interface{},
) error {
	machineFreshInstance := &clusterv1alpha1.CnctMachine{}
	err := r.Get(
		context.Background(),
		client.ObjectKey{
			Namespace: machineInstance.GetNamespace(),
			Name:      machineInstance.GetName(),
		}, machineFreshInstance)
	if err != nil {
		return err
	}

	machineFreshInstance.ObjectMeta.Annotations = machineInstance.ObjectMeta.Annotations
	machineFreshInstance.Finalizers = machineInstance.Finalizers
	machineFreshInstance.Status.Phase = machineInstance.Status.Phase
	machineFreshInstance.Status.KubernetesVersion = machineInstance.Status.KubernetesVersion
	machineFreshInstance.Status.LastUpdated = &metav1.Time{Time: time.Now()}

	err = r.Update(context.Background(), machineFreshInstance)
	if err != nil {
		return err
	}

	r.Eventf(machineFreshInstance, eventType,
		string(event), string(eventMessage), args...)

	return nil
}

func getCluster(c client.Client, namespace string, clusterName string) (*clusterv1alpha1.CnctCluster, error) {

	clusterKey := client.ObjectKey{
		Namespace: namespace,
		Name:      clusterName,
	}

	clusterInstance := &clusterv1alpha1.CnctCluster{}
	err := c.Get(context.Background(), clusterKey, clusterInstance)
	if err != nil {
		return nil, err
	}

	return clusterInstance, nil
}

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

package cluster

import (
	"context"
	"time"

	"github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/common"
	clusterv1alpha1 "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/cert"
	"github.com/samsung-cnct/cma-ssh/pkg/util"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("CnctCluster-controller")

// Add creates a new Cluster Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCluster{
		Client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		EventRecorder: mgr.GetRecorder("ClusterController"),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("cluster-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to Cluster
	err = c.Watch(&source.Kind{Type: &clusterv1alpha1.CnctCluster{}}, &handler.EnqueueRequestForObject{})
	return err
}

var _ reconcile.Reconciler = &ReconcileCluster{}

// ReconcileCluster reconciles a Cluster object
type ReconcileCluster struct {
	client.Client
	scheme *runtime.Scheme
	record.EventRecorder
}

// Reconcile reads that state of the cluster for a Cluster object and makes changes based on the state read
// and what is in the Cluster.Spec
// Automatically generate RBAC rules to allow the Controller to read and write Deployments
// +kubebuilder:rbac:groups=cluster.cnct.sds.samsung.com,resources=cnctclusters;cnctmachines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
func (r *ReconcileCluster) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// Fetch the Cluster instance
	cluster := &clusterv1alpha1.CnctCluster{}
	err := r.Get(context.Background(), request.NamespacedName, cluster)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, return. Created objects are automatically garbage collected.
			// log.Error(err, "could not find cluster", "cluster", request)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "error reading object cluster", "request", request)
		return reconcile.Result{}, err
	}

	if !cluster.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is being deleted
		if util.ContainsString(cluster.ObjectMeta.Finalizers, clusterv1alpha1.ClusterFinalizer) {
			log.Info("deleting cluster...")
			// update status to "deleting"
			if cluster.Status.Phase != common.StoppingClusterPhase {
				cluster.Status.Phase = common.StoppingClusterPhase
				err = r.updateStatus(cluster, corev1.EventTypeNormal,
					common.ResourceStateChange, common.MessageResourceStateChange,
					cluster.GetName(), common.StoppingClusterPhase)
				if err != nil {
					log.Error(err, "could not update status of cluster", "cluster", cluster)
					return reconcile.Result{}, err
				}
			}

			// if no Machines left to be deleted
			// set phase to deleted so secrets can be deleted and finalizer
			// can be removed
			cluster.Status.Phase = common.StoppingClusterPhase
		}
	}

	switch cluster.Status.Phase {
	case "":
		if err := createClusterSecrets(r.Client, cluster, r.scheme); err != nil {
			return reconcile.Result{Requeue: true}, err
		}
		log.Info("cluster secrets created")
		cluster.Status.Phase = common.RunningClusterPhase
		cluster.ObjectMeta.Finalizers = append(cluster.ObjectMeta.Finalizers, clusterv1alpha1.ClusterFinalizer)
		err = r.updateStatus(
			cluster,
			corev1.EventTypeNormal,
			common.ResourceStateChange,
			common.MessageResourceStateChange,
			cluster.GetName(),
			common.RunningClusterPhase,
		)
		if err != nil {
			log.Error(err, "could not update cluster status", "cluster", cluster)
			return reconcile.Result{Requeue: true}, err
		}
	case common.StoppingClusterPhase:
		var machines clusterv1alpha1.CnctMachineList
		err := r.Client.List(context.Background(), &client.ListOptions{Namespace: cluster.Namespace}, &machines)
		if err != nil {
			return reconcile.Result{}, errors.Wrap(err, "could not list machines")
		}
		var pendingMachines []clusterv1alpha1.CnctMachine
		for _, machine := range machines.Items {
			err := r.Client.Delete(context.Background(), &machine)
			if apierrors.IsNotFound(err) {
				continue
			} else if err != nil {
				return reconcile.Result{}, errors.Wrap(err, "could not delete machine")
			}
			var m clusterv1alpha1.CnctMachine
			err = r.Client.Get(context.Background(), client.ObjectKey{Name: machine.Name, Namespace: machine.Namespace}, &m)
			if apierrors.IsNotFound(err) {
				continue
			} else if err != nil {
				return reconcile.Result{}, errors.Wrap(err, "could not get machine after deletion")
			} else {
				pendingMachines = append(pendingMachines, m)
			}
		}
		if len(pendingMachines) != 0 {
			log.Info("cluster deletion pending on machine deletion", "pending machines", len(pendingMachines))
			return reconcile.Result{RequeueAfter: 1 * time.Second}, nil
		}
		var secret corev1.Secret
		err = r.Get(context.Background(), client.ObjectKey{Name: "cluster-private-key", Namespace: cluster.Namespace}, &secret)
		if err != nil {
			return reconcile.Result{}, err
		}
		secret.SetFinalizers(nil)
		err = r.Update(context.Background(), &secret)
		if err != nil {
			return reconcile.Result{}, err
		}
		cluster.ObjectMeta.Finalizers =
			util.RemoveString(cluster.ObjectMeta.Finalizers, clusterv1alpha1.ClusterFinalizer)
		return reconcile.Result{}, r.Update(context.Background(), cluster)
	}

	return reconcile.Result{}, err
}

func createClusterSecrets(k8sClient client.Client, cluster *clusterv1alpha1.CnctCluster, scheme *runtime.Scheme) error {
	bundle, err := cert.NewCABundle()
	if err != nil {
		log.Error(err, "could not create a new ca cert bundle")
		return err
	}

	dataMap := map[string][]byte{}
	bundle.MergeWithMap(dataMap)
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster-private-key",
			Namespace:  cluster.Namespace,
			Finalizers: []string{"foregroundDeletion"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: dataMap,
	}
	if err := controllerutil.SetControllerReference(cluster, &secret, scheme); err != nil {
		return errors.Wrap(err, "could not set owner ref on cluster secret")
	}
	return k8sClient.Create(context.Background(), &secret)
}

func (r *ReconcileCluster) updateStatus(clusterInstance *clusterv1alpha1.CnctCluster, eventType string,
	event common.ControllerEvents, eventMessage common.ControllerEvents, args ...interface{}) error {

	clusterFreshInstance := &clusterv1alpha1.CnctCluster{}
	err := r.Get(
		context.Background(),
		client.ObjectKey{
			Namespace: clusterInstance.GetNamespace(),
			Name:      clusterInstance.GetName(),
		}, clusterFreshInstance)
	if err != nil {
		return err
	}

	clusterFreshInstance.Status.LastUpdated = &metav1.Time{Time: time.Now()}
	clusterFreshInstance.Status.Phase = clusterInstance.Status.Phase
	clusterFreshInstance.Status.APIEndpoint = clusterInstance.Status.APIEndpoint
	clusterFreshInstance.ObjectMeta.Finalizers = clusterInstance.ObjectMeta.Finalizers

	err = r.Update(context.Background(), clusterFreshInstance)
	if err != nil {
		return err
	}

	r.Eventf(clusterFreshInstance, eventType,
		string(event), string(eventMessage), args...)

	return nil
}

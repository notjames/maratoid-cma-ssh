package machine

import (
	"context"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/kubectl/drain"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clusterv1alpha1 "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/maas"
)

func (r *ReconcileMachine) handleDelete(
	machine *clusterv1alpha1.CnctMachine,
	cluster *clusterv1alpha1.CnctCluster,
) error {
	log.Info("handling machine delete")

	// If the machine does not have a system id yet then it has not been
	// acquired or deployed in maas so we can just delete it.
	if machine.Status.SystemId == "" || !cluster.DeletionTimestamp.IsZero() {
		if err := deleteMachine(r, machine); err != nil {
			return errors.Wrap(err, "could not delete machine object")
		}
	}
	log.Info("creating clientset for remote cluster")
	var secret corev1.Secret
	err := r.Get(
		context.Background(),
		client.ObjectKey{
			Name:      "cluster-private-key",
			Namespace: cluster.Namespace,
		},
		&secret,
	)
	if apierrors.IsNotFound(err) {
		if err := deleteMachine(r, machine); err != nil {
			return errors.Wrap(err, "could not delete machine object")
		}
	} else if err != nil {
		return errors.Wrap(err, "could not get cluster secret")
	}
	configData, ok := secret.Data[corev1.ServiceAccountKubeconfigKey]
	if !ok || len(configData) == 0 {
		return errNotReady("no kubeconfig in secret")
	}
	config, err := clientcmd.NewClientConfigFromBytes(configData)
	if err != nil {
		return errors.Wrap(err, "could not create client config")
	}
	restConfig, err := config.ClientConfig()
	if err != nil {
		return errors.Wrap(err, "could not create rest config")
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return errors.Wrap(err, "could not create clientset")
	}

	// if the machine node has already been deleted then we don't need to
	// worry about cordoning and draining the node. We can just release the
	// machine in maas.
	node, err := clientset.CoreV1().Nodes().Get(machine.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if delerr := deleteMachine(r, machine); delerr != nil {
			return errors.Wrap(delerr, "could not delete machine object")
		}
	} else if err != nil {
		return errors.Wrapf(err, "could not get node %s", machine.Name)
	}
	log.Info("cordoning remote node")
	cordonHelper := drain.NewCordonHelper(node)
	if cordonHelper.UpdateIfRequired(true) {
		err, patchErr := cordonHelper.PatchOrReplace(clientset)
		if patchErr != nil {
			klog.Error(patchErr)
		}
		if err != nil {
			return errors.Wrap(err, "could not cordon node")
		}
	}
	drainer := drain.Helper{
		Force:               true,
		IgnoreAllDaemonSets: true,
		Client:              clientset,
		GracePeriodSeconds:  1,
		// FIXME: is this a reasonable limit
		Timeout: 10 * time.Minute,
	}
	list, errs := drainer.GetPodsForDeletion(node.Name)
	if errs != nil {
		err = utilerrors.NewAggregate(errs)
		return errors.Wrap(err, "could not list pods on node for eviction")
	}

	policyGroupVersion, err := drain.CheckEvictionSupport(drainer.Client)
	if err != nil {
		return err
	}
	if len(policyGroupVersion) > 0 {
		log.Info("evicting pods on node")
		returnCh := make(chan error, 1)
		for _, pod := range list.Pods() {
			go func(pod corev1.Pod, returnCh chan error) {
				for {
					err := drainer.EvictPod(pod, policyGroupVersion)
					if err == nil {
						break
					} else if apierrors.IsNotFound(err) {
						returnCh <- nil
					} else if apierrors.IsTooManyRequests(err) {
						time.Sleep(5 * time.Second)
					} else {
						returnCh <- errors.Wrap(err, "could not evict pod")
					}
				}
				err := wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
					p, err := clientset.CoreV1().Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
					if apierrors.IsNotFound(err) || (p != nil && p.ObjectMeta.UID != pod.ObjectMeta.UID) {
						return true, nil
					} else if err != nil {
						return false, err
					} else {
						return false, nil
					}
				})
				returnCh <- err
			}(pod, returnCh)
		}
	} else {
		log.Info("deleting pods on node")
		pods := list.Pods()
		for _, pod := range pods {
			err := drainer.DeletePod(pod)
			if err != nil && !apierrors.IsNotFound(err) {
				return errors.Wrap(err, "could not delete pods")
			}
		}
		err := wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
			var pendingPods []corev1.Pod
			for i, pod := range pods {
				p, err := clientset.CoreV1().Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) || (p != nil && p.ObjectMeta.UID != pod.ObjectMeta.UID) {
					continue
				} else if err != nil {
					return false, err
				} else {
					pendingPods = append(pendingPods, list.Pods()[i])
				}
			}
			pods = pendingPods
			if len(pendingPods) > 0 {
				return false, nil
			}
			return true, nil
		})
		if err != nil {
			return errors.Wrap(err, "error while polling for deleted pods")
		}
	}

	log.Info("removing remote node from cluster")
	err = clientset.CoreV1().Nodes().Delete(machine.Name, &metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "could not delete node")
	}

	if err := deleteMachine(r, machine); err != nil {
		return errors.Wrap(err, "could not delete machine object")
	}

	return nil
}

func deleteMachine(r *ReconcileMachine, machine *clusterv1alpha1.CnctMachine) error {
	systemID := machine.Status.SystemId
	if systemID != "" {
		if err := r.MAASClient.Delete(context.Background(), &maas.DeleteRequest{SystemID: systemID}); err != nil {
			return errors.Wrapf(err, "could not delete machine %s with system id %q", machine.Name, *machine.Spec.ProviderID)
		}
	}

	var fresh clusterv1alpha1.CnctMachine
	r.Client.Get(context.Background(), client.ObjectKey{Namespace: machine.Namespace, Name: machine.Name}, &fresh)
	fresh.Finalizers = []string{}
	if err := r.Client.Update(context.Background(), &fresh); err != nil {
		return errors.Wrap(err, "could not remove finalizer")
	}
	return nil
}

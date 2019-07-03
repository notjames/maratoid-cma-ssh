package apiserver

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog"
	clientlib "sigs.k8s.io/controller-runtime/pkg/client"

	addonsv1alpha1 "github.com/samsung-cnct/cma-ssh/pkg/apis/addons/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/common"
	v1alpha "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/controller/machineset"
	pb "github.com/samsung-cnct/cma-ssh/pkg/generated/api"
	"github.com/samsung-cnct/cma-ssh/pkg/util"
)

func (s *Server) CreateCluster(ctx context.Context, in *pb.CreateClusterMsg) (*pb.CreateClusterReply, error) {
	// get client
	client := s.Manager.GetClient()

	// create namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: in.Name,
		},
	}
	err := client.Create(ctx, namespace)
	if err != nil {
		klog.Errorf("Failed to create cluster namespace %s: %q", namespace.Name, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	// create cluster
	clusterObject := &v1alpha.CnctCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      in.Name,
			Namespace: in.Name,
			Labels: map[string]string{
				"controller-tools.k8s.io": "1.0",
			},
		},
		Spec: v1alpha.ClusterSpec{
			KubernetesVersion: in.K8SVersion,
		},
	}
	err = client.Create(ctx, clusterObject)
	if err != nil {
		klog.Errorf("Failed to create cluster object %s: %q", clusterObject.GetName(), err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	// create control plane machines
	// TODO (zachpuck): handle count (currently only creates 1 machine)
	{
		machineConfig := in.ControlPlaneNodes
		machineLabels := map[string]string{}
		for _, label := range machineConfig.Labels {
			machineLabels[label.Name] = label.Value
		}
		machineLabels["controller-tools.k8s.io"] = "1.0"

		machineObject := &v1alpha.CnctMachine{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "control-plane-",
				Namespace:    in.Name,
				Labels:       machineLabels,
			},
			Spec: v1alpha.MachineSpec{
				Roles:        []common.MachineRoles{common.MachineRoleMaster, common.MachineRoleEtcd},
				InstanceType: machineConfig.InstanceType,
			},
		}

		err = client.Create(ctx, machineObject)
		if err != nil {
			klog.Errorf("Failed to create control plane machine object %s: %q", machineObject.GetName(), err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	// create worker machineSet(s)
	for _, machineSetConfig := range in.WorkerNodePools {
		machineLabels := map[string]string{}
		for _, label := range machineSetConfig.Labels {
			machineLabels[label.Name] = label.Value
		}
		machineLabels["controller-tools.k8s.io"] = "1.0"
		machineLabels["node-pool"] = machineSetConfig.Name

		machineSetObject := &v1alpha.CnctMachineSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      machineSetConfig.Name,
				Namespace: in.Name,
				Labels:    machineLabels,
			},
			Spec: v1alpha.MachineSetSpec{
				Replicas: int(machineSetConfig.Count),
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"node-pool": machineSetConfig.Name,
					},
				},
				MachineTemplate: v1alpha.MachineTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Labels: machineLabels,
					},
					Spec: v1alpha.MachineSpec{
						Roles:        []common.MachineRoles{common.MachineRoleWorker},
						InstanceType: machineSetConfig.InstanceType,
					},
				},
			},
		}

		// validate machineSet
		isValid, err := machineset.ValidateMachineSet(machineSetObject)
		if !isValid || err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		err = client.Create(ctx, machineSetObject)
		if err != nil {
			klog.Errorf("Failed to create worker machine set object %s: %q", machineSetObject.GetName(), err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	// create addons appbundle for prometheus operator
	{
		appBundleObject := &addonsv1alpha1.AppBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prometheus-addons-appbundle",
				Namespace: in.Name,
			},
			Spec: addonsv1alpha1.AppBundleSpec{
				Image: "quay.io/samsung_cnct/cma-prometheus-installer:latest",
			},
		}
		errAppBundle := client.Create(ctx, appBundleObject)
		if errAppBundle != nil {
			klog.Errorf("Failed to create prometheus addons app bundle for cluster", in.Name, errAppBundle)
		}
	}

	return &pb.CreateClusterReply{
		Ok: true,
		Cluster: &pb.ClusterItem{
			Name:   in.Name,
			Status: pb.ClusterStatus_PROVISIONING,
		},
	}, nil
}

func (s *Server) GetCluster(ctx context.Context, in *pb.GetClusterMsg) (*pb.GetClusterReply, error) {

	// get client
	client := s.Manager.GetClient()

	// get kubeconfig secret
	kubeconfigBytes, err := GetKubeConfig(in.Name, s.Manager)
	if err != nil {
		klog.Infof("Could not get kubeconfig secret for cluster %s: %q", in.Name, err)
	}

	// get cluster
	clusterInstance := &v1alpha.CnctCluster{}
	err = client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: in.Name,
			Name:      in.Name,
		}, clusterInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.Name, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetClusterReply{
		Ok: true,
		Cluster: &pb.ClusterDetailItem{
			Name:       in.Name,
			Status:     TranslateClusterStatus(clusterInstance.Status.Phase),
			Kubeconfig: string(kubeconfigBytes),
		},
	}, nil
}

func (s *Server) GetClusterNodesStatus(ctx context.Context, in *pb.GetClusterNodesStatusMsg) (*pb.GetClusterNodesStatusReply, error) {
	// initialize cluster
	cluster := pb.GetClusterNodesStatusReply{}

	// create client
	client := s.Manager.GetClient()

	// get cluster instance
	clusterInstance := &v1alpha.CnctCluster{}

	err := client.Get(
		ctx,
		clientlib.ObjectKey{
			// this may just need to be clusterInstance.Namespace
			Namespace: in.ClusterName,
			Name:      in.ClusterName,
		}, clusterInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.ClusterName, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	if in.ClusterName != clusterInstance.Namespace {
		klog.Warningln("If the cluster name and namespace are different, then GetNodePool() may fail.")
	}

	machineList := &v1alpha.CnctMachineList{}
	cluster.Name = clusterInstance.Name

	err = client.List(
		ctx,
		&clientlib.ListOptions{
			Namespace: clusterInstance.GetNamespace(),
		}, machineList)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.ClusterName, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	cluster.Count = int32(len(machineList.Items))

	for _, clusterMachine := range machineList.Items {
		machine := pb.GetClusterNodesStatusReply_MachineStatus{}

		machine.MaasSystemId = clusterMachine.Status.SystemId
		machine.K8SVersion = clusterMachine.Status.KubernetesVersion
		machine.MaasIPAddr = clusterMachine.Status.SshConfig.Host
		machine.K8SNodeStatus = string(clusterMachine.Status.Phase)
		machine.MaasHostname = clusterMachine.ObjectMeta.Annotations["maas-hostname"]

		if clusterMachine.Status.SystemId == "" {
			machine.MaasSystemId = "Waiting for Machine Instantiation..."
		}

		cluster.Machines = append(cluster.Machines, &machine)
	}

	return &cluster, nil
}

func (s *Server) DeleteCluster(ctx context.Context, in *pb.DeleteClusterMsg) (*pb.DeleteClusterReply, error) {

	// get client
	client := s.Manager.GetClient()

	// get cluster
	clusterInstance := &v1alpha.CnctCluster{}
	err := client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: in.Name,
			Name:      in.Name,
		}, clusterInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.Name, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	err = client.Delete(ctx, clusterInstance)
	if err != nil {
		klog.Errorf("Could not delete cluster cr %s: %q", in.Name, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	namespace := &corev1.Namespace{}
	err = client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: "",
			Name:      in.Name,
		}, namespace)
	if err == nil {
		err = client.Delete(ctx, namespace)
		if err != nil {
			klog.Errorf("Could not delete namespace %s: %q", in.Name, err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	return &pb.DeleteClusterReply{Ok: true, Status: "Deleted"}, nil
}

func (s *Server) GetClusterList(ctx context.Context, in *pb.GetClusterListMsg) (reply *pb.GetClusterListReply, err error) {
	// get client
	client := s.Manager.GetClient()

	// get list of cluster CRs
	clusterCrList := &v1alpha.CnctClusterList{}
	err = client.List(
		ctx,
		&clientlib.ListOptions{LabelSelector: labels.Everything()},
		clusterCrList)
	if err != nil {
		klog.Errorf("could not list cluster CRs: %q", err)
		return &pb.GetClusterListReply{
			Ok: false,
		}, err
	}

	if len(clusterCrList.Items) == 0 {
		return &pb.GetClusterListReply{
			Ok:       true,
			Clusters: nil,
		}, nil
	}

	var clusters []*pb.ClusterItem
	for _, cluster := range clusterCrList.Items {
		clusterStatus := TranslateClusterStatus(cluster.Status.Phase)

		clusters = append(clusters, &pb.ClusterItem{
			Name:   cluster.GetName(),
			Status: clusterStatus,
		})
	}

	return &pb.GetClusterListReply{
		Ok:       true,
		Clusters: clusters,
	}, nil
}

func (s *Server) GetUpgradeClusterInformation(ctx context.Context, in *pb.GetUpgradeClusterInformationMsg) (*pb.GetUpgradeClusterInformationReply, error) {
	// TODO: Do not hard code this list.
	return &pb.GetUpgradeClusterInformationReply{
		Versions: util.KubernetesVersions(),
	}, nil
}

func (s *Server) UpgradeCluster(ctx context.Context, in *pb.UpgradeClusterMsg) (*pb.UpgradeClusterReply, error) {
	// get client
	client := s.Manager.GetClient()

	// get cluster
	clusterInstance := &v1alpha.CnctCluster{}
	err := client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: in.Name,
			Name:      in.Name,
		}, clusterInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.Name, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	// update version
	clusterInstance.Spec.KubernetesVersion = in.Version
	err = client.Update(ctx, clusterInstance)
	if err != nil {
		klog.Errorf("Could update cluster %s: %q", in.Name, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.UpgradeClusterReply{
		Ok: true,
	}, nil
}

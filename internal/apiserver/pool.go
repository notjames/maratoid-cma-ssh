package apiserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	clientlib "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/common"
	clusterv1alpha "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/controller/machineset"
	pb "github.com/samsung-cnct/cma-ssh/pkg/generated/api"
)

func (s *Server) AddNodePool(ctx context.Context, in *pb.AddNodePoolMsg) (*pb.AddNodePoolReply, error) {
	// get client
	client := s.Manager.GetClient()

	// get cluster
	clusterInstance := &clusterv1alpha.CnctCluster{}
	err := client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: in.ClusterName,
			Name:      in.ClusterName,
		}, clusterInstance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.ClusterName, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	// add worker machineSet(s)
	for _, machineSetConfig := range in.WorkerNodePools {
		machineLabels := map[string]string{}
		for _, label := range machineSetConfig.Labels {
			machineLabels[label.Name] = label.Value
		}
		machineLabels["controller-tools.k8s.io"] = "1.0"
		machineLabels["node-pool"] = machineSetConfig.Name

		machineSetObject := &clusterv1alpha.CnctMachineSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      machineSetConfig.Name,
				Namespace: in.ClusterName,
				Labels:    machineLabels,
			},
			Spec: clusterv1alpha.MachineSetSpec{
				Replicas: int(machineSetConfig.Count),
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"node-pool": machineSetConfig.Name,
					},
				},
				MachineTemplate: clusterv1alpha.MachineTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Labels: machineLabels,
					},
					Spec: clusterv1alpha.MachineSpec{
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
			klog.Errorf("Failed to add worker machine set object %s: %q", machineSetObject.GetName(), err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &pb.AddNodePoolReply{
		Ok: true,
	}, nil
}

func (s *Server) DeleteNodePool(ctx context.Context, in *pb.DeleteNodePoolMsg) (*pb.DeleteNodePoolReply, error) {
	// get client
	client := s.Manager.GetClient()

	// get cluster
	clusterInstance := &clusterv1alpha.CnctCluster{}
	err := client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: in.ClusterName,
			Name:      in.ClusterName,
		}, clusterInstance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.ClusterName, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	for _, machineSetName := range in.NodePoolNames {
		// get machineSet by name
		machineSet := &clusterv1alpha.CnctMachineSet{}
		err = client.Get(
			ctx,
			clientlib.ObjectKey{
				Namespace: in.ClusterName,
				Name:      machineSetName,
			}, machineSet)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, status.Error(codes.NotFound, err.Error())
			}
			klog.Errorf("Could not query for machineSet %s, in cluster %s: %q", machineSetName, in.ClusterName, err)
			return nil, status.Error(codes.Internal, err.Error())
		}

		err = client.Delete(ctx, machineSet)
		if err != nil {
			klog.Errorf("Could not delete machineSet %s in cluster %s: %q", machineSetName, in.ClusterName, err)
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &pb.DeleteNodePoolReply{Ok: true}, nil
}

func (s *Server) ScaleNodePool(ctx context.Context, in *pb.ScaleNodePoolMsg) (*pb.ScaleNodePoolReply, error) {
	// get client
	client := s.Manager.GetClient()

	// get cluster
	clusterInstance := &clusterv1alpha.CnctCluster{}
	err := client.Get(
		ctx,
		clientlib.ObjectKey{
			Namespace: in.ClusterName,
			Name:      in.ClusterName,
		}, clusterInstance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		klog.Errorf("Could not query for cluster %s: %q", in.ClusterName, err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	for _, nodePool := range in.NodePools {
		// get machineSet by name
		machineSet := &clusterv1alpha.CnctMachineSet{}
		err = client.Get(
			ctx,
			clientlib.ObjectKey{
				Namespace: in.ClusterName,
				Name:      nodePool.Name,
			}, machineSet)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, status.Error(codes.NotFound, err.Error())
			}
			klog.Errorf("Could not query for machineSet %s, in cluster %s: %q", nodePool.Name, in.ClusterName, err)
			return nil, status.Error(codes.Internal, err.Error())
		}

		// update count
		machineSet.Spec.Replicas = int(nodePool.Count)
		err = client.Update(ctx, machineSet)
		if err != nil {
			klog.Errorf("Could not update machineSet %s count on cluster %s: %q", nodePool.Name, in.ClusterName, err)
			return nil, status.Error(codes.Internal, err.Error())
		}

	}
	return &pb.ScaleNodePoolReply{Ok: true}, nil
}

# Purpose

The e2e tests are used to test end to end functionality of the cma-ssh api.  The cms-ssh api is the primary endpoint
for cma-ssh functionality, and the cluster-manager-api(cma) api provides an end user endpoint to include callbacks
and access to other providers.  There are scripts here to test both api endpoints (cma, and cma-ssh).

# Developer Context

When making changes to cma-ssh, the developer and possibly reviewer should run the `full-test-cma-ssh.sh` script which will e2e test the cma-ssh api.

# How to run `full-test-cma-ssh.sh`

```bash
# create a k8s cluster to use for cma-ssh
minikube start
kubectl create clusterrolebinding superpowers --clusterrole=cluster-admin --user=system:serviceaccount:kube-system:default
kubectl create rolebinding superpowers --clusterrole=cluster-admin --user=system:serviceaccount:kube-system:default
kubectl apply -f crd

# build and run cma-ssh
cd $GOPATH/src/github.com/samsung-cnct/cma-ssh
go1.12.4 build -o cma-ssh cmd/cma-ssh/main.go
MAAS_API_URL=http://192.168.2.24:5240/MAAS MAAS_API_VERSION_KEY=2.0 MAAS_API_KEY=<your maas key> ./cma-ssh --logtostderr

# run the e2e script
cd $GOPATH/src/github.com/samsung-cnct/cma-ssh/test/e2e
source ./testEnvs.sh
./full-test-cma-ssh.sh

# Look at test output and final status
full-test-cma-ssh PASSED

```

# CI Pipeline Context

TBD.  CI needs access to the MaaS environment in order to test end to end provisioning.

# Deprecated

This set of tests using the Cluster Manager API pipeline through CMA SSH, which will install a managed cluster on pre-provisioned hosts. In order for this specific set of tests to work, you *must* have at least two IP addresses (machines, vms, etc) running BEFORE these tests can be performed.

# How to run

1.  populate the environment with required VARs (defaults are provided)  See all of the environmentals needed in full-test.sh
2.  execute `full-test.sh`

## Sequence of the tests
(FIX UP - WIP)
1.  create a client cluster via a parent CMA-SSH helper:
    `create-cluster.sh`
2.  get the kubeconfig for the client cluster from the parent cluster
    K8S API `get-kubeconfig()` in `full-test.sh`
3.  create a simple system in the client cluster (using nginx-ingress)
4.  verify the simple system functions
5.  tear down the client cluster: `delete-cluster.sh`

#!/bin/bash

DEBUG=${DEBUG:-1}

[[ $DEBUG == 1 ]] && \
  {
    set -o xtrace
  }

set -o errexit
set -o nounset
set -o pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly CLIENT_KUBECONFIG="$CLUSTER_NAME-kubeconfig.yaml"

get_kubeconfig()
{
  "${__dir}/get-kubeconfig" > "${CLIENT_KUBECONFIG}"
}


test_provisioning(){
  provisioning=$("${__dir}/cma-ssh-create")
  echo "create output:"
  echo $provisioning
  if echo "$provisioning" | grep -o PROVISIONING; then
    echo "Cluster is PROVISIONING"
  else
    echo "Cluster is NOT PROVISIONING"
    return 1
  fi
  return 0
}

test_running()
{
  # wait up to 20 minutes for cluster RUNNING
  for tries in $(seq 1 120); do

    if [[ $("${__dir}"/cma-ssh-get | jq -Mr '.cluster.status') == RUNNING ]]; then
      echo "Cluster is RUNNING"
      echo "elapsed seconds=$(( 10 * $tries ))"
      return 0
    else
      echo "Cluster is NOT RUNNING"
    fi
    sleep 10
  done
  echo "Timed out waiting for RUNNING status"
  return 1
}

test_ready()
{
  get_kubeconfig
  for tries in $(seq 1 120); do
    nodes=$(kubectl get nodes --kubeconfig "$CLIENT_KUBECONFIG")
    echo "$nodes"

    # check for not ready
    if echo "$nodes" | grep -qo NotReady; then
      echo "Node(s) NotReady"
    # there should be 2 ready nodes in the cma-ssh-create  
    elif [[ $(echo "$nodes" | grep -o Ready | wc -l) -ge 2 ]]; then
      echo "All Nodes Are Ready"
      rm "$CLIENT_KUBECONFIG"
      return 0
    else
      echo "waiting for all nodes ready"
    fi
    sleep 10
  done
  echo "Timed out waiting for all nodes Ready"
  rm "$CLIENT_KUBECONFIG"
  return 1
}

test_delete(){
  delete=$("${__dir}/cma-ssh-delete")
  echo "delete output:"
  echo $delete

  # wait up to 20 minutes for cluster delete complete
  for tries in $(seq 1 120); do
    deleted=$("${__dir}/cma-get")
    if echo $deleted | grep -o "STOPPING"; then
      echo "Cluster DELETE is NOT COMPLETE"
    else
      echo "Cluster DELETE is COMPLETE"
      echo "elapsed seconds=$(( 10 * $tries ))"
      return 0
    fi
    sleep 10
  done
  echo "Timed out waiting for DELETE to finish"
  return 1
}

main()
{
  fullstatus="PASSED"

  # test create is provisioning
  if ! test_provisioning; then
     echo "test_provisioning FAILED"
  else
     echo "test_provisioning PASSED"
  fi

  if ! test_running; then
    echo "test_running FAILED"
    fullstatus="FAILED"
  else
    echo "test_running PASSED"
  fi

  if ! test_ready; then
    echo "test_ready FAILED"
    fullstatus="FAILED"
  else
    echo "test_ready PASSED"
  fi
  sleep 4
  if ! test_delete; then
    echo "test_delete FAILED"
    fullstatus="FAILED"
  else
    echo "test_delete PASSED"
  fi

  echo "full-test-cma-ssh $fullstatus"
  if [ "$fullstatus" == "FAILED" ]; then
    exit 1
  fi

  exit 0
}

main

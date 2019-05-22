#!/bin/bash

# Uncomment this if using the cma api service and running tests as a job
#export CLUSTER_API=http://cma-cluster-manager-api

# Uncomment this if testing the cma api locally
#export CLUSTER_API=http://localhost:9050

# Uncomment this if testing the cma-ssh api locally
export CLUSTER_API=http://localhost:9020

export CMA_CALLBACK_URL=https://webhook.site/#/15a7f31c-5b57-41fc-bd70-a8dec0f56442
export CMA_CALLBACK_REQUESTID=12345

export CLUSTER_NAME=cluster
export K8S_VERSION=1.13.5


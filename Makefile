VERSION = v0.1.0
DIR := ${CURDIR}
REGISTRY ?= quay.io/samsung_cnct
TARGET= cma-ssh
GOTARGET = github.com/samsung-cnct/$(TARGET)
IMAGE = $(REGISTRY)/$(TARGET)-dependencies
BUILDMNT = /go/src/$(GOTARGET)
DOCKER = docker
DOCKER_BUILD ?= $(DOCKER) run --rm -v $(DIR):$(BUILDMNT) -w $(BUILDMNT) $(IMAGE) /bin/sh -c
HOST_GOOS ?= $(shell go env GOOS)
HOST_GOARCH ?= $(shell go env GOARCH)
GO = go1.12.4
GO_SYSTEM_FLAGS ?= GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) GO111MODULE=on GOPROXY=https://proxy.golang.org
GOFILES = $(shell find ./ -type f -name '*.go')

all: cma-ssh

clean:
	rm -rf bin
	rm -f cma-ssh

$(GO):
	GO111MODULE=off go get -u golang.org/dl/$(GO)
	GO111MODULE=off $(GO) download

cma-ssh: $(GOFILES)
	CGO_ENABLED=0 $(GO_SYSTEM_FLAGS) $(GO) build -o $(TARGET) ./cmd/cma-ssh

bin:
	mkdir bin

bin/deepcopy-gen: bin
	$(GO_SYSTEM_FLAGS) GOBIN=$(DIR)/bin $(GO) install k8s.io/code-generator/cmd/deepcopy-gen

bin/controller-gen: bin
	$(GO_SYSTEM_FLAGS) GOBIN=$(DIR)/bin $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen

bin/kustomize: bin
	$(GO_SYSTEM_FLAGS) GOBIN=$(DIR)/bin $(GO) install sigs.k8s.io/kustomize

.PHONY: build-dependencies-container

build-dependencies-container:
	docker build -t $(IMAGE) -f build/docker/build-tools/Dockerfile --build-arg GO_VERSION=$(GO) build/docker/build-tools

test: build-dependencies-container
	$(DOCKER_BUILD) 'go test -v ./...'

generate: bin/deepcopy-gen
	PATH=${CURDIR}/bin:$$($(GO) env GOROOT)/bin go generate ./...

clean-test: build-dependencies-container
	$(DOCKER_BUILD) '$(GO_SYSTEM_FLAGS) $(GO) build -o $(TARGET) ./cmd/cma-ssh'

# protoc generates the proto buf api
protoc: build-dependencies-container
	$(DOCKER_BUILD) build/generators/api.sh
	$(DOCKER_BUILD) build/generators/swagger-dist-adjustment.sh
	$(MAKE) generate

# Generate manifests e.g. CRD, RBAC etc.
# generate parts of helm chart
manifests: bin/controller-gen bin/kustomize
	bin/controller-gen crd --output-dir ${CURDIR}/crd
	bin/controller-gen rbac --name rbac --output-dir ${CURDIR}/rbac
	mkdir -p ${CURDIR}/build/kustomize/crd/protected/cluster/base
	mkdir -p ${CURDIR}/build/kustomize/crd/unprotected/cluster/base
	mkdir -p ${CURDIR}/build/kustomize/crd/protected/machine/base
	mkdir -p ${CURDIR}/build/kustomize/crd/unprotected/machine/base
	mkdir -p ${CURDIR}/build/kustomize/crd/protected/machineset/base
	mkdir -p ${CURDIR}/build/kustomize/crd/unprotected/machineset/base
	mkdir -p ${CURDIR}/build/kustomize/crd/protected/appbundle/base
	mkdir -p ${CURDIR}/build/kustomize/crd/unprotected/appbundle/base
	mkdir -p ${CURDIR}/build/kustomize/rbac/role/base
	mkdir -p ${CURDIR}/build/kustomize/rbac/rolebinding/base
	cp -rf ${CURDIR}/rbac/rbac_role.yaml ${CURDIR}/build/kustomize/rbac/role/base
	cp -rf ${CURDIR}/rbac/rbac_role_binding.yaml ${CURDIR}/build/kustomize/rbac/rolebinding/base
	cp -rf ${CURDIR}/crd/cluster_v1alpha1_cnctcluster.yaml ${CURDIR}/build/kustomize/crd/unprotected/cluster/base
	cp -rf ${CURDIR}/crd/cluster_v1alpha1_cnctcluster.yaml ${CURDIR}/build/kustomize/crd/protected/cluster/base
	cp -rf ${CURDIR}/crd/cluster_v1alpha1_cnctmachine.yaml ${CURDIR}/build/kustomize/crd/unprotected/machine/base
	cp -rf ${CURDIR}/crd/cluster_v1alpha1_cnctmachine.yaml ${CURDIR}/build/kustomize/crd/protected/machine/base
	cp -rf ${CURDIR}/crd/cluster_v1alpha1_cnctmachineset.yaml ${CURDIR}/build/kustomize/crd/protected/machineset/base
	cp -rf ${CURDIR}/crd/cluster_v1alpha1_cnctmachineset.yaml ${CURDIR}/build/kustomize/crd/unprotected/machineset/base
	cp -rf ${CURDIR}/crd/addons_v1alpha1_appbundle.yaml ${CURDIR}/build/kustomize/crd/unprotected/appbundle/base
	cp -rf ${CURDIR}/crd/addons_v1alpha1_appbundle.yaml ${CURDIR}/build/kustomize/crd/protected/appbundle/base
	output=$$(bin/kustomize build build/kustomize/rbac/role); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/RBAC/rbac_role.yaml
	output=$$(bin/kustomize build build/kustomize/rbac/rolebinding); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/RBAC/rbac_role_binding.yaml
	output=$$(bin/kustomize build build/kustomize/crd/protected/cluster); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD-protected/cluster_v1alpha1_cnctcluster.yaml
	output=$$(bin/kustomize build build/kustomize/crd/protected/machine); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD-protected/custer_v1alpha1_cnctmachine.yaml
	output=$$(bin/kustomize build build/kustomize/crd/protected/machineset); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD-protected/cluster_v1alpha1_cnctmachineset.yaml
	output=$$(bin/kustomize build build/kustomize/crd/protected/appbundle); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD-protected/addons_v1alpha1_appbundle.yaml
	output=$$(bin/kustomize build build/kustomize/crd/unprotected/cluster); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD/cluster_v1alpha1_cnctcluster.yaml
	output=$$(bin/kustomize build build/kustomize/crd/unprotected/machine); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD/cluster_v1alpha1_cnctmachine.yaml
	output=$$(bin/kustomize build build/kustomize/crd/unprotected/machineset); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD/cluster_v1alpha1_cnctmachineset.yaml
	output=$$(bin/kustomize build build/kustomize/crd/unprotected/appbundle); echo "$$output" > ${CURDIR}/deployments/helm/cma-ssh/CRD/addons_v1alpha1_appbundle.yaml


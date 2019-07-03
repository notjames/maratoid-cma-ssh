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
	$(GO_SYSTEM_FLAGS) GOOS=linux $(GO) build -o bin/deepcopy-gen ./vendor/k8s.io/code-generator/cmd/deepcopy-gen

bin/controller-gen: bin
	$(GO_SYSTEM_FLAGS) GOBIN=$(DIR)/bin $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen

bin/kustomize: bin
	$(GO_SYSTEM_FLAGS) GOBIN=$(DIR)/bin $(GO) install sigs.k8s.io/kustomize

bin/protoc-gen-go: bin
	$(GO_SYSTEM_FLAGS) GOOS=linux $(GO) build -o bin/protoc-gen-go ./vendor/github.com/golang/protobuf/protoc-gen-go

bin/protoc-gen-grpc-gateway: bin
	$(GO_SYSTEM_FLAGS) GOOS=linux $(GO) build -o bin/protoc-gen-grpc-gateway ./vendor/github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway

bin/protoc-gen-swagger: bin
	$(GO_SYSTEM_FLAGS) GOOS=linux $(GO) build -o bin/protoc-gen-swagger ./vendor/github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger

bin/protoc-gen-doc: bin
	$(GO_SYSTEM_FLAGS) GOOS=linux $(GO) build -o bin/protoc-gen-doc ./vendor/github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc

.PHONY: build-dependencies-container

build-dependencies-container:
	docker build -t $(IMAGE) -f build/docker/build-tools/Dockerfile --build-arg GO_VERSION=$(GO) build/docker/build-tools

test: build-dependencies-container
	$(DOCKER_BUILD) 'go test -v ./...'

generate: bin/deepcopy-gen
	$(DOCKER_BUILD) 'PATH=/go/src/github.com/samsung-cnct/cma-ssh/bin:$$PATH go generate ./...'

clean-test: build-dependencies-container
	$(DOCKER_BUILD) '$(GO_SYSTEM_FLAGS) $(GO) build -o $(TARGET) ./cmd/cma-ssh'

# protoc generates the proto buf api
protoc: build-dependencies-container bin/protoc-gen-go bin/protoc-gen-grpc-gateway bin/protoc-gen-swagger bin/protoc-gen-doc
	$(DOCKER_BUILD) build/generators/api.sh
	$(DOCKER_BUILD) build/generators/swagger-dist-adjustment.sh
	$(MAKE) generate

# Generate manifests e.g. CRD, RBAC etc.
# generate parts of helm chart
manifests: bin/controller-gen bin/kustomize
	bin/controller-gen crd --output-dir ${CURDIR}/crd
	bin/controller-gen rbac --name rbac --output-dir ${CURDIR}/rbac
	mkdir -p ${CURDIR}/build/kustomize/rbac/role/base
	mkdir -p ${CURDIR}/build/kustomize/rbac/rolebinding/base
	cp -rf ${CURDIR}/rbac/rbac_role.yaml ${CURDIR}/build/kustomize/rbac/role/base
	cp -rf ${CURDIR}/rbac/rbac_role_binding.yaml ${CURDIR}/build/kustomize/rbac/rolebinding/base
	bin/kustomize build build/kustomize/rbac/role > ${CURDIR}/deployments/helm/cma-ssh/RBAC/rbac_role.yaml
	bin/kustomize build build/kustomize/rbac/rolebinding > ${CURDIR}/deployments/helm/cma-ssh/RBAC/rbac_role_binding.yaml

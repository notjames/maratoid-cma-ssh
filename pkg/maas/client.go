/*
Copyright 2019 The Kubernetes Authors.

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

package maas

import (
	"context"
	"encoding/base64"
	"fmt"

	"k8s.io/klog"

	"github.com/juju/gomaasapi"
)

type Client interface {
	Create(context.Context, *CreateRequest) (*CreateResponse, error)
	Delete(context.Context, *DeleteRequest) error
	Images() []string
}

type client struct {
	gomaasapi.Controller
}

type NewClientParams struct {
	ApiURL     string
	ApiVersion string
	ApiKey     string
}

func NewClient(params *NewClientParams) (Client, error) {
	controller, err := gomaasapi.NewController(gomaasapi.ControllerArgs{
		BaseURL: params.ApiURL,
		APIKey:  params.ApiKey})
	if err != nil {
		return nil, fmt.Errorf("error creating controller with version: %v", err)
	}

	return &client{Controller: controller}, nil
}

type CreateRequest struct {
	// ProviderID is a unique value created by the k8s controller and used
	// to identify the machine allocated by MAAS. Before a machine is
	// allocated, a MAAS tag containing the ProviderID must be set. This
	// ensures the machine can be managed even if the k8s controller fails
	// after allocation.
	// TODO: Implement. Cf. https://samsung-cnct.atlassian.net/browse/HS19-158
	ProviderID string

	// Distro is the name of the OS image and kernel to install/boot.
	Distro string

	// InstanceType is used to filter the machines to allocate by MAAS tags.
	// These tags would have been specified on machines to correspond
	// to different machine types desired.  If InstanceType is empty any machine can
	// be allocated.
	InstanceType string

	// Userdata is passed to the machine on boot and contains cloud-init
	// configuration.
	Userdata string
}

type CreateResponse struct {
	// ProviderID is the unique value passed in CreateRequest.
	ProviderID string

	// IPAddresses is a list of IP addresses assigned to the machine.
	IPAddresses []string

	// SystemID is a unique value created by the MAAS controller and used
	// to manage machines. Each MAAS machine has a SystemID generated during
	// the Enlistment phase. This ID is used to refer to allocated machines
	// when modifying them (including when releasing them). For more information
	// regarding MAAS see the official documentation or webook:
	// https://docs.maas.io/2.5/en/api
	// https://github.com/davidewatson/cluster-api-webhooks-maas/pull/1
	// TODO: Replace or augement this with ProviderID.
	SystemID string
}

// Create creates a machine
func (c *client) Create(ctx context.Context, request *CreateRequest) (*CreateResponse, error) {
	klog.Infof("Creating machine %s", request.ProviderID)

	// Allocate MAAS machine
	allocateArgs := gomaasapi.AllocateMachineArgs{Tags: []string{request.InstanceType}}
	m, _, err := c.Controller.AllocateMachine(allocateArgs)
	if err != nil {
		klog.Errorf("Create failed to allocate machine %s: %v", request.ProviderID, err)
		return nil, fmt.Errorf("error allocating machine %s: %v", request.ProviderID, err)
	}

	// Deploy MAAS machine
	startArgs := gomaasapi.StartArgs{
		UserData:     base64.StdEncoding.EncodeToString([]byte(request.Userdata)),
		DistroSeries: request.Distro,
	}
	err = m.Start(startArgs)
	if err != nil {
		klog.Errorf("Create failed to deploy machine %s: %v", request.ProviderID, err)
		err := c.Delete(ctx, &DeleteRequest{ProviderID: request.ProviderID,
			SystemID: m.SystemID()})
		if err != nil {
			klog.Errorf("Create failed to release machine %s: %v", request.ProviderID, err)
		}
		return nil, err
	}

	klog.Infof("Created machine %s (%s)", request.ProviderID, m.SystemID())

	return &CreateResponse{
		ProviderID:  request.ProviderID,
		IPAddresses: m.IPAddresses(),
		SystemID:    m.SystemID(),
	}, nil
}

func (c *client) Images() (images []string) {
	br, err := c.BootResources()
	if err != nil {
		return
	}

	for _, v := range br {
		if v.Type() != "Uploaded" {
			continue
		}
		images = append(images, v.Name())
	}
	return
}

type DeleteRequest struct {
	// ProviderID is the unique value passed in CreateRequest.
	ProviderID string
	// SystemID is the unique value passed in CreateResponse.
	SystemID string
}

type DeleteResponse struct {
}

// Delete deletes a machine
func (c client) Delete(ctx context.Context, request *DeleteRequest) error {
	if request.SystemID == "" {
		klog.Warningf("can not delete  machine %s, providerID not set", request.ProviderID)
		return fmt.Errorf("machine %s has not been created", request.ProviderID)
	}

	// Release MAAS machine
	releaseArgs := gomaasapi.ReleaseMachinesArgs{SystemIDs: []string{request.SystemID}}
	if err := c.Controller.ReleaseMachines(releaseArgs); err != nil {
		klog.Warningf("error releasing machine %s (%s): %v", request.ProviderID, request.SystemID, err)
		return nil
	}

	return nil
}

type UpdateRequest struct {
	// ProviderID is the unique value passed in CreateRequest.
	ProviderID string
}

// Update updates a machine
func (c client) Update(ctx context.Context, request *UpdateRequest) error {
	return nil
}

type ExistsRequest struct {
	// ProviderID is the unique value passed in CreateRequest.
	ProviderID string
}

// Exists test for the existence of a machine
func (c client) Exist(ctx context.Context, request *ExistsRequest) (bool, error) {
	// ProviderID will be nil until Create completes successfully
	if request.ProviderID == "" {
		return false, nil
	}

	// Get list of machines with tag
	machineArgs := gomaasapi.MachinesArgs{SystemIDs: []string{request.ProviderID}}
	machines, err := c.Controller.Machines(machineArgs)
	if err != nil {
		return false, fmt.Errorf("error listing machine %s: %v", request.ProviderID, err)
	}
	if len(machines) != 1 {
		return false, fmt.Errorf("expected 1 machine %s, found %d", request.ProviderID, len(machines))
	}

	return true, nil
}

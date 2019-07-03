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

package cmd

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/soheilhy/cmux"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"

	"github.com/samsung-cnct/cma-ssh/pkg/apis"
	"github.com/samsung-cnct/cma-ssh/pkg/apiserver"
	"github.com/samsung-cnct/cma-ssh/pkg/controller"
	"github.com/samsung-cnct/cma-ssh/pkg/controller/machine"
	"github.com/samsung-cnct/cma-ssh/pkg/crd"
	"github.com/samsung-cnct/cma-ssh/pkg/maas"
	"github.com/samsung-cnct/cma-ssh/pkg/webhook"
)

const (
	apiURLKey     = "api_url"
	apiVersionKey = "api_version"
	apiKeyKey     = "api_key"
)

var (
	rootCmd = &cobra.Command{
		Use:   "cma-ssh",
		Short: "CMA SSH Operator",
		Long:  `CMA SSH provider operator`,
		Run: func(cmd *cobra.Command, args []string) {
			operator(cmd)
		},
	}
)

// init configures input and output.
func init() {
	rootCmd.Flags().Int("port", 9020, "Port to listen on")

	viper.SetEnvPrefix("maas")
	viper.BindEnv(apiURLKey)
	viper.BindEnv(apiVersionKey)
	viper.BindEnv(apiKeyKey)
	viper.AutomaticEnv()
}

// Execute runs the root cobra command
func Execute() {
	klogFlagSet := &flag.FlagSet{}
	klog.InitFlags(klogFlagSet)
	rootCmd.Flags().AddGoFlagSet(flag.CommandLine)
	rootCmd.Flags().AddGoFlagSet(klogFlagSet)
	err := flag.CommandLine.Parse([]string{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	log.SetLogger(klogr.New())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func operator(cmd *cobra.Command) {
	// Get a config to talk to the apiserver
	klog.Info("setting up client for manager")
	cfg, err := config.GetConfig()
	if err != nil {
		klog.Errorf("unable to set up client config: %q", err)
		os.Exit(1)
	}

	if err := installCrdsIfNotFound(cfg); err != nil {
		klog.Errorf("unable to install crds: %q", err)
		os.Exit(1)
	}

	// Create a new Cmd to provide shared dependencies and start components
	klog.Info("setting up manager")
	mgr, err := manager.New(cfg, manager.Options{})
	if err != nil {
		klog.Errorf("unable to set up overall controller manager: %q", err)
		os.Exit(1)
	}

	klog.Info("Registering Components.")

	// Setup Scheme for all resources
	klog.Info("setting up scheme")
	if err := apis.AddToScheme(mgr.GetScheme()); err != nil {
		klog.Errorf("unable add APIs to scheme: %q", err)
		os.Exit(1)
	}

	// Setup all Controllers
	klog.Info("Setting up controller")
	if err := controller.AddToManager(mgr); err != nil {
		klog.Errorf("unable to register controllers to the manager: %q", err)
		os.Exit(1)
	}

	// TODO: Determine if the Cluster controller needs access to MAAS
	apiURL := viper.GetString(apiURLKey)
	apiVersion := viper.GetString(apiVersionKey)
	apiKey := viper.GetString(apiKeyKey)
	maasClient, err := maas.NewClient(&maas.NewClientParams{ApiURL: apiURL, ApiVersion: apiVersion, ApiKey: apiKey})
	if err != nil {
		klog.Errorf("unable to create MAAS client for machine controller: %q", err)
		os.Exit(1)
	}
	err = machine.AddWithActuator(mgr, maasClient)
	if err != nil {
		klog.Errorf("unable to register machine controller with the manager: %q", err)
		os.Exit(1)
	}

	klog.Info("setting up webhooks")
	if err := webhook.AddToManager(mgr); err != nil {
		klog.Errorf("unable to register webhooks to the manager: %q", err)
		os.Exit(1)
	}

	// get flags
	portNumber, err := cmd.Flags().GetInt("port")
	if err != nil {
		klog.Errorf("Could not get port: %q", err)
	}

	klog.Info("Creating Web Server")
	tcpMux := createWebServer(&apiserver.ServerOptions{PortNumber: portNumber}, mgr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		klog.Infof("Starting to serve requests on port %d", portNumber)
		if err := tcpMux.Serve(); err != nil {
			klog.Errorf("unable serve requests: %q", err)
			os.Exit(1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		klog.Info("Starting the Cmd")
		if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
			klog.Errorf("unable to run the manager: %q", err)
			os.Exit(1)
		}
	}()

	klog.Info("Waiting for controllers to shut down gracefully")
	wg.Wait()
}

func createWebServer(options *apiserver.ServerOptions, manager manager.Manager) cmux.CMux {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", options.PortNumber))
	if err != nil {
		panic(err)
	}
	tcpMux := cmux.New(conn)

	apiServer := apiserver.NewApiServer(manager, tcpMux)
	apiServer.AddServersToMux(options)

	return apiServer.GetMux()
}

func installCrdsIfNotFound(cfg *rest.Config) error {
	cs, err := clientset.NewForConfig(cfg)
	if err != nil {
		return err
	}
	_, err = cs.ApiextensionsV1beta1().CustomResourceDefinitions().Get("cnctclusters.cluster.cnct.sds.samsung.com", v1.GetOptions{})
	if errors.IsNotFound(err) {
		if err := createCRD(cs, "/cluster_v1alpha1_cnctcluster.yaml"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, err = cs.ApiextensionsV1beta1().CustomResourceDefinitions().Get("cnctmachines.cluster.cnct.sds.samsung.com", v1.GetOptions{})
	if errors.IsNotFound(err) {
		if err := createCRD(cs, "/cluster_v1alpha1_cnctmachine.yaml"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, err = cs.ApiextensionsV1beta1().CustomResourceDefinitions().Get("cnctmachinesets.cluster.cnct.sds.samsung.com", v1.GetOptions{})
	if errors.IsNotFound(err) {
		if err := createCRD(cs, "/cluster_v1alpha1_cnctmachineset.yaml"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, err = cs.ApiextensionsV1beta1().CustomResourceDefinitions().Get("appbundles.addons.cnct.sds.samsung.com",
		v1.GetOptions{})
	if errors.IsNotFound(err) {
		if err := createCRD(cs, "/addons_v1alpha1_appbundle.yaml"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func createCRD(cs *clientset.Clientset, file string) error {
	f, err := crd.Crd.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := yaml.NewYAMLOrJSONDecoder(f, 100)
	var newCrd v1beta1.CustomResourceDefinition
	err = dec.Decode(&newCrd)
	if err != nil {
		return err
	}
	_, err = cs.ApiextensionsV1beta1().CustomResourceDefinitions().Create(&newCrd)
	return err
}

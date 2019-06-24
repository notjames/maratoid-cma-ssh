package machine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/common"
	clusterv1alpha1 "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/cert"
	"github.com/samsung-cnct/cma-ssh/pkg/maas"
	"github.com/samsung-cnct/cma-ssh/pkg/util"
)

const InstanceTypeNodeLabelKey = "beta.kubernetes.io/instance-type="

// notReadyError signals the controller that something is not available yet but
// may be available in the future.
type notReadyError string

func (e notReadyError) Error() string {
	return string(e)
}

// unrecoverableError signals the controller that the current machine state can
// never be fixed without user intervention.
type unrecoverableError struct {
	reason string
}

func (e unrecoverableError) Error() string {
	return e.reason
}

// releaseError signals that the controller must release a machine that has been
// allocated.
type releaseError struct {
	systemID string
	err      error
}

func (e releaseError) Error() string {
	return e.err.Error()
}

type clientEventer interface {
	client.Client
	record.EventRecorder
}

type creator struct {
	k8sClient  clientEventer
	maasClient *maas.Client
	machine    *clusterv1alpha1.CnctMachine
	err        error

	// derived types
	isMaster       bool
	cluster        clusterv1alpha1.CnctCluster
	clientset      *kubernetes.Clientset
	secret         corev1.Secret
	token          string
	createRequest  maas.CreateRequest
	createResponse maas.CreateResponse
}

func create(k8sClient clientEventer, maasClient *maas.Client, machine *clusterv1alpha1.CnctMachine) error {
	log.Info("checking if machine is master")
	var isMaster bool
	for _, v := range machine.Spec.Roles {
		if v == common.MachineRoleMaster {
			isMaster = true
			break
		}
	}
	c := &creator{k8sClient: k8sClient, maasClient: maasClient, machine: machine}
	c.isMaster = isMaster
	if isMaster {
		c.getCluster()
		c.getSecret()
		c.prepareMaasRequest()
		c.doMaasCreate()
		c.createKubeconfig()
		c.updateCluster()
		c.updateMachine()
	} else {
		c.getCluster()
		c.getSecret()
		c.createClientsetFromSecret()
		c.checkIfTokenExists()
		c.createToken()
		c.checkApiserverAddress()
		c.prepareMaasRequest()
		c.doMaasCreate()
		c.updateMachine()
	}
	return c.err
}

func (c *creator) getCluster() {
	if c.err != nil {
		return
	}

	log.Info("getting cluster from namespace")
	// Get cluster from machine's namespace.
	var clusters clusterv1alpha1.CnctClusterList
	c.err = c.k8sClient.List(
		context.Background(),
		&client.ListOptions{Namespace: c.machine.Namespace},
		&clusters,
	)
	if c.err != nil {
		return
	}
	if len(clusters.Items) == 0 {
		log.Info("no cluster in namespace, requeue request")
		c.err = notReadyError("no cluster in namespace")
		return
	}
	c.cluster = clusters.Items[0]
}

func (c *creator) getSecret() {
	if c.err != nil {
		return
	}
	log.Info("getting the secret cert bundle")
	c.err = c.k8sClient.Get(context.Background(), client.ObjectKey{Name: "cluster-private-key", Namespace: c.machine.Namespace}, &c.secret)
}

func (c *creator) createClientsetFromSecret() {
	if c.err != nil || c.isMaster {
		return
	}

	log.Info("creating clientset from cert bundle")
	configData, ok := c.secret.Data[corev1.ServiceAccountKubeconfigKey]
	if !ok || len(configData) == 0 {
		c.err = notReadyError("no kubeconfig in secret")
		return
	}
	config, err := clientcmd.NewClientConfigFromBytes(configData)
	if err != nil {
		c.err = err
		return
	}
	restConfig, err := config.ClientConfig()
	if err != nil {
		c.err = err
		return
	}
	c.clientset, c.err = kubernetes.NewForConfig(restConfig)
}

func (c *creator) checkIfTokenExists() {
	if c.err != nil || c.isMaster {
		return
	}
	log.Info("checking for existing tokens on managed cluster")
	list, err := c.clientset.CoreV1().
		Secrets(metav1.NamespaceSystem).
		List(metav1.ListOptions{FieldSelector: "type=" + string(corev1.SecretTypeBootstrapToken)})
	if err != nil {
		e, ok := err.(*apierrors.StatusError)
		if !ok {
			c.err = notReadyError(err.Error())
		} else {
			c.err = e
		}
		return
	}

	// find the first non-expired token
	// FIXME (apo): if the token expires before kubeadm can run then the
	//  node will never join the cluster.
	for _, secret := range list.Items {
		expires, ok := secret.Data["expiration"]
		if ok && len(expires) > 0 {
			t, err := time.Parse(time.RFC3339, string(expires))
			if err != nil || t.Before(time.Now().Add(30*time.Minute)) {
				continue
			}
		}
		log.Info("found an existing token", "token", secret.Name)
		c.token = fmt.Sprintf("%s.%s", secret.Data["token-id"], secret.Data["token-secret"])
		return
	}
}

func (c *creator) createToken() {
	if c.err != nil || c.isMaster || c.token != "" {
		return
	}

	log.Info("creating join token")
	tokBuf := make([]byte, 3)
	_, c.err = io.ReadFull(rand.Reader, tokBuf)
	if c.err != nil {
		return
	}
	tokSecBuf := make([]byte, 8)
	_, c.err = io.ReadFull(rand.Reader, tokSecBuf)
	if c.err != nil {
		return
	}
	c.err = createBootstrapToken(c.clientset, fmt.Sprintf("%x", tokBuf), fmt.Sprintf("%x", tokSecBuf))
	if c.err != nil {
		return
	}
	c.token = fmt.Sprintf("%x.%x", tokBuf, tokSecBuf)
}

func createBootstrapToken(clientset *kubernetes.Clientset, tokenID, tokenSecret string) error {
	token := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bootstrap-token-" + tokenID,
			Namespace: "kube-system",
		},
		Type: corev1.SecretTypeBootstrapToken,
		Data: map[string][]byte{
			"description":                    []byte("Bootstrap token created by cma-ssh"),
			"token-id":                       []byte(tokenID),
			"token-secret":                   []byte(tokenSecret),
			"expiration":                     []byte(time.Now().Add(1 * time.Hour).Format(time.RFC3339)),
			"usage-bootstrap-authentication": []byte("true"),
			"usage-bootstrap-signing":        []byte("true"),
			"auth-extra-groups":              []byte("system:bootstrappers:kubeadm:default-node-token"),
		},
	}
	if _, err := clientset.CoreV1().Secrets("kube-system").Create(&token); err != nil {
		return errors.Wrap(err, "could not create token secret")
	}
	return nil
}

func (c *creator) checkApiserverAddress() {
	if c.err != nil || c.isMaster {
		return
	}

	log.Info("checking if apiendpoint is set on cluster")
	apiserverAddress := c.cluster.Status.APIEndpoint
	if apiserverAddress == "" {
		c.err = notReadyError(fmt.Sprintf("%s cluster APIEndpoint is not set", c.cluster.Name))
		return
	}
}

func (c *creator) getNodeLabels() string {
	var sb strings.Builder
	labels := c.machine.GetLabels()
	for k, v := range labels {
		label := fmt.Sprintf("%s=%s,", k, v)
		sb.WriteString(label)
	}
	sb.WriteString(InstanceTypeNodeLabelKey)
	sb.WriteString(c.machine.Spec.InstanceType)
	return sb.String()
}

func (c *creator) prepareMaasRequest() {
	if c.err != nil {
		return
	}

	log.Info("preparing maas request")
	var bundle *cert.CABundle
	bundle, c.err = cert.CABundleFromMap(c.secret.Data)
	if c.err != nil {
		return
	}
	var userdata string
	if c.isMaster {
		userdata, c.err = masterUserdata(c, bundle)
	} else {
		userdata, c.err = workerUserdata(c, bundle)
	}
	// TODO: ProviderID should be unique. One way to ensure this is to generate
	// a UUID. Cf. k8s.io/apimachinery/pkg/util/uuid
	providerID := fmt.Sprintf("%s-%s", c.cluster.Name, c.machine.Name)
	distro := getImage(c.maasClient, "ubuntu-xenial", c.cluster.Spec.KubernetesVersion, c.machine.Spec.InstanceType)
	if distro == "" {
		c.err = unrecoverableError{reason: fmt.Sprintf("there is no matching image in MaaS: osVersion=%s, k8sVersion=%s, instanceType=%s", "ubuntu-xenial", c.cluster.Spec.KubernetesVersion, c.machine.Spec.InstanceType)}
		return
	}
	c.createRequest = maas.CreateRequest{
		ProviderID:   providerID,
		Distro:       distro,
		Userdata:     userdata,
		InstanceType: c.machine.Spec.InstanceType,
	}
}

const masterUserdataTmplText = `#cloud-config
write_files:
 - encoding: b64
   content: {{ .Tar }}
   owner: root:root
   path: /etc/kubernetes/pki/certs.tar
   permissions: '0600'
 - owner: root:root
   path: /var/tmp/masterconfig.yaml
   permissions: '0644'
   content: |
     apiVersion: kubeadm.k8s.io/v1beta1
     kind: InitConfiguration
     nodeRegistration:
       kubeletExtraArgs:
         node-labels: {{ .NodeLabels }}
     ---
     apiVersion: kubeadm.k8s.io/v1beta1
     kind: ClusterConfiguration
     networking:
       podSubnet: "10.244.0.0/16"

runcmd:
 - [ sh, -c, "swapoff -a" ]
 - [ sh, -c, "sed -ri.bak '/ swap / s/^(.*)$/#\\1/g' /etc/fstab" ]
 - [ sh, -c, "tar xf /etc/kubernetes/pki/certs.tar -C /etc/kubernetes/pki" ]
 - [ sh, -c, "kubeadm init --node-name {{ .Name }}  --config /var/tmp/masterconfig.yaml" ]
 - [ sh, -c, "kubectl --kubeconfig /etc/kubernetes/admin.conf apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml" ]
 - [ sh, -c, "kubectl --kubeconfig /etc/kubernetes/admin.conf taint node {{ .Name }} node-role.kubernetes.io/master:NoSchedule-" ]

output : { all : '| tee -a /var/log/cloud-init-output.log' }
`

var masterUserdataTmpl = template.Must(template.New("master").Parse(masterUserdataTmplText))

func masterUserdata(c *creator, bundle *cert.CABundle) (string, error) {
	caTar, err := bundle.ToTar()
	if err != nil {
		return "", err
	}
	var userdata strings.Builder
	data := struct {
		Name       string
		Tar        string
		NodeLabels string
	}{
		Name:       c.machine.Name,
		Tar:        caTar,
		NodeLabels: c.getNodeLabels(),
	}
	if err := masterUserdataTmpl.Execute(&userdata, data); err != nil {
		return "", err
	}
	return userdata.String(), nil
}

const workerUserdataTmplText = `#cloud-config
write_files:
 - owner: root:root
   path: /var/tmp/workerconfig.yaml
   permissions: '0644'
   content: |
     apiVersion: kubeadm.k8s.io/v1beta1
     kind: JoinConfiguration
     caCertPath: /etc/kubernetes/pki/ca.crt
     discovery:
       bootstrapToken:
         apiServerEndpoint: {{ .APIEndpoint }}
         token: {{ .Token }}
         caCertHashes:
         - {{ .CertHash }}
       tlsBootstrapToken: {{ .Token }}
     nodeRegistration:
       kubeletExtraArgs:
         node-labels: {{ .NodeLabels }}

runcmd:
 - [ sh, -c, "swapoff -a" ]
 - [ sh, -c, "sed -ri.bak '/ swap / s/^(.*)$/#\\1/g' /etc/fstab" ]
 - [ sh, -c, "kubeadm join --node-name {{ .Name }} --config /var/tmp/workerconfig.yaml" ]

output : { all : '| tee -a /var/log/cloud-init-output.log' }
`

var workerUserdataTmpl = template.Must(template.New("worker").Parse(workerUserdataTmplText))

func workerUserdata(c *creator, bundle *cert.CABundle) (string, error) {
	certBlock, _ := pem.Decode(bundle.K8s)
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", errors.Wrap(err, "could not parse k8s certificate for public key")
	}
	hash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	caHash := fmt.Sprintf("sha256:%x", hash)
	var buf strings.Builder
	data := struct {
		Name        string
		Token       string
		CertHash    string
		APIEndpoint string
		NodeLabels  string
	}{
		Name:        c.machine.Name,
		Token:       c.token,
		CertHash:    caHash,
		APIEndpoint: c.cluster.Status.APIEndpoint,
		NodeLabels:  c.getNodeLabels(),
	}
	if err := workerUserdataTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (c *creator) doMaasCreate() {
	if c.err != nil {
		return
	}

	log.Info("calling create on maas")
	createResponse, err := c.maasClient.Create(context.Background(), &c.createRequest)
	if err != nil {
		c.err = err
		return
	}

	if len(createResponse.IPAddresses) == 0 {
		log.Info("machine ip is nil, releasing", "maas create response", createResponse)
		c.err = c.maasClient.Delete(
			context.Background(),
			&maas.DeleteRequest{
				ProviderID: createResponse.ProviderID,
				SystemID:   createResponse.SystemID,
			},
		)
		return
	}
	c.createResponse = *createResponse
}

func (c *creator) createKubeconfig() {
	if c.err != nil || !c.isMaster {
		return
	}

	log.Info("creating kubeconfig")
	bundle, err := cert.CABundleFromMap(c.secret.Data)
	if err != nil {
		c.err = err
		return
	}

	log.Info("create kubeconfig")
	kubeconfig, err := bundle.Kubeconfig(c.cluster.Name, "https://"+c.createResponse.IPAddresses[0]+":6443")
	if err != nil {
		c.err = err
		return
	}

	log.Info("add kubeconfig to cluster-private-key secret")
	c.secret.Data[corev1.ServiceAccountKubeconfigKey] = kubeconfig
	c.err = c.k8sClient.Update(context.Background(), &c.secret)
}

func (c *creator) updateMachine() {
	if c.err != nil {
		return
	}

	// Add the finalizer
	if !util.ContainsString(c.machine.Finalizers, clusterv1alpha1.MachineFinalizer) {
		log.Info("adding finalizer to machine")
		c.machine.Finalizers = append(c.machine.Finalizers, clusterv1alpha1.MachineFinalizer)
	}

	log.Info("update machine status to ready")
	// update status to "creating"
	c.machine.Status.Phase = common.ProvisioningMachinePhase
	c.machine.Status.KubernetesVersion = c.cluster.Spec.KubernetesVersion
	c.machine.Status.SystemId = c.createResponse.SystemID
	c.machine.Status.SshConfig.Host = c.createResponse.IPAddresses[0]
	// Check if machine object has existing annotations
	if c.machine.ObjectMeta.Annotations == nil {
		c.machine.ObjectMeta.Annotations = map[string]string{}
	}
	// TODO: (zachpuck) Move these Annotations to Status
	c.machine.ObjectMeta.Annotations["maas-ip"] = c.createResponse.IPAddresses[0]
	c.machine.ObjectMeta.Annotations["maas-system-id"] = c.createResponse.SystemID

	err := c.k8sClient.Update(context.Background(), c.machine)
	if err != nil {
		c.err = releaseError{systemID: c.createResponse.SystemID, err: err}
		return
	}

	c.k8sClient.Event(
		c.machine,
		corev1.EventTypeNormal,
		"ResourceStateChange",
		"set Finalizer and OwnerReferences",
	)
}

func (c *creator) updateCluster() {
	if c.err != nil || !c.isMaster {
		return
	}

	log.Info("updating cluster")
	log.Info("updating cluster api endpoint")
	var fresh clusterv1alpha1.CnctCluster
	err := c.k8sClient.Get(
		context.Background(),
		client.ObjectKey{
			Namespace: c.cluster.GetNamespace(),
			Name:      c.cluster.GetName(),
		},
		&fresh,
	)
	if err != nil {
		c.err = releaseError{err: err, systemID: c.createResponse.SystemID}
	}

	fresh.Status.APIEndpoint = c.createResponse.IPAddresses[0] + ":6443"
	fresh.Status.LastUpdated = &metav1.Time{Time: time.Now()}
	err = c.k8sClient.Update(context.Background(), &fresh)
	if err != nil {
		c.err = releaseError{err: err, systemID: c.createResponse.SystemID}
		return
	}

	c.k8sClient.Event(
		&fresh,
		corev1.EventTypeNormal,
		"ResourceStateChange",
		"set cluster APIEndpoint",
	)
}

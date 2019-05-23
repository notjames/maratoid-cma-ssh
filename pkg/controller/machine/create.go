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
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/common"
	clusterv1alpha1 "github.com/samsung-cnct/cma-ssh/pkg/apis/cluster/v1alpha1"
	"github.com/samsung-cnct/cma-ssh/pkg/cert"
	"github.com/samsung-cnct/cma-ssh/pkg/maas"
	"github.com/samsung-cnct/cma-ssh/pkg/util"
)

const InstanceTypeNodeLabelKey = "beta.kubernetes.io/instance-type="

type errNotReady string

func (e errNotReady) Error() string {
	return string(e)
}

type errRelease struct {
	systemID string
	err      error
}

func (e errRelease) Error() string {
	return e.err.Error()
}

// TODO (zachpuck): figure out a better name
type creatorClients struct {
	k8sClient       client.Client
	maasClient      maas.Client
	secretInterface v1.SecretInterface
}

type creator struct {
	creatorClients

	machine *clusterv1alpha1.CnctMachine
	cluster *clusterv1alpha1.CnctCluster
	secret  *corev1.Secret
	err     error

	// derived types
	isMaster      bool
	clientset     *kubernetes.Clientset
	token         string
	createRequest *maas.CreateRequest
	host          string
}

func create(k8sClient client.Client, maasClient maas.Client, machine *clusterv1alpha1.CnctMachine, cluster *clusterv1alpha1.CnctCluster, secret *corev1.Secret) error {
	log.Info("checking if machine is master")
	var isMaster bool
	for _, v := range machine.Spec.Roles {
		if v == common.MachineRoleMaster {
			isMaster = true
			break
		}
	}
	c := &creator{creatorClients: creatorClients{k8sClient: k8sClient, maasClient: maasClient}}
	c.isMaster = isMaster
	c.machine = machine
	c.cluster = cluster
	c.secret = secret
	if isMaster {
		return createMaster(c)
	} else {
		return createWorker(c)
	}
}

func createMaster(c *creator) error {
	var err error
	c.createRequest, err = prepareMaasRequest(c)
	if err != nil {
		return errors.Wrap(err, "could not prepare maas request")
	}
	c.host, err = doMaasCreate(c)
	if err != nil {
		return errors.Wrap(err, "could not create maas node")
	}
	if err := createKubeconfig(c); err != nil {
		return errors.Wrap(err, "could not create kubeconfig")
	}
	if err := updateCluster(c); err != nil {
		return errors.Wrap(err, "could not update cluster status")
	}
	if err := updateMachine(c); err != nil {
		return errors.Wrap(err, "could not update machine to ready")
	}
	return nil
}

func createWorker(c *creator) error {
	if c.cluster.Status.APIEndpoint == "" {
		return errNotReady(fmt.Sprintf("%s cluster APIEndpoint is not set", c.cluster.Name))
	}
	kubeconfig, ok := c.secret.Data[corev1.ServiceAccountKubeconfigKey]
	if !ok || len(kubeconfig) == 0 {
		return errNotReady("no kubeconfig in secret")
	}

	var err error
	c.clientset, err = createClientsetFromSecret(kubeconfig)
	if err != nil {
		return err
	}
	c.token, err = getExistingToken(c.clientset.CoreV1().Secrets(metav1.NamespaceSystem).List)
	if err != nil {
		return err
	} else if c.token == "" {
		c.token, err = createToken(c)
		if err != nil {
			return errors.Wrap(err, "could not create a bootstrap token")
		}
	}
	c.createRequest, err = prepareMaasRequest(c)
	if err != nil {
		return errors.Wrap(err, "could not prepare maas request")
	}
	c.host, err = doMaasCreate(c)
	if err != nil {
		return errors.Wrap(err, "could not create maas node")
	}
	return updateMachine(c)
}

func createClientsetFromSecret(kubeconfig []byte) (*kubernetes.Clientset, error) {
	log.Info("creating clientset from cert bundle")
	config, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
	if err != nil {
		return nil, errors.Wrap(err, "could not create new config")
	}
	restConfig, err := config.ClientConfig()
	if err != nil {
		return nil, errors.Wrap(err, "could not create rest config")
	}
	return kubernetes.NewForConfig(restConfig)
}

// getExistingToken uses the secretListFn to list the bootstrap token secrets on
// the remote cluster. If there is an unexpired token in the returned list we
// return that token. If we get a not found error or the all the tokens have
// expired then we return an empty string and nil error. In all other cases we
// return an error. Users must check both error and string returned.
func getExistingToken(secretListFn func(options metav1.ListOptions) (*corev1.SecretList, error)) (string, error) {
	opt := metav1.ListOptions{FieldSelector: "type=" + string(corev1.SecretTypeBootstrapToken)}
	list, err := secretListFn(opt)
	if apierrors.IsNotFound(err) {
		return "", nil
	} else if err != nil {
		return "", errNotReady(err.Error())
	}
	// find the first non-expired token
	for _, secret := range list.Items {
		expires, ok := secret.Data["expiration"]
		if ok && len(expires) > 0 {
			t, err := time.Parse(time.RFC3339, string(expires))
			if err != nil || t.Before(time.Now()) {
				continue
			}
		}
		log.Info("found an existing token")
		token := fmt.Sprintf("%s.%s", list.Items[0].Data["token-id"], list.Items[0].Data["token-secret"])
		return token, nil
	}
	return "", nil
}

func createToken(c *creator) (string, error) {
	log.Info("creating join token")
	tokBuf := make([]byte, 3)
	_, err := io.ReadFull(rand.Reader, tokBuf)
	if err != nil {
		return "", err
	}
	tokSecBuf := make([]byte, 8)
	_, err = io.ReadFull(rand.Reader, tokSecBuf)
	if err != nil {
		return "", err
	}
	err = createBootstrapToken(c.secretInterface, fmt.Sprintf("%x", tokBuf), fmt.Sprintf("%x", tokSecBuf))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x.%x", tokBuf, tokSecBuf), nil
}

func createBootstrapToken(s v1.SecretInterface, tokenID, tokenSecret string) error {
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
	if _, err := s.Create(&token); err != nil {
		return errors.Wrap(err, "could not create token secret")
	}
	return nil
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

func prepareMaasRequest(c *creator) (*maas.CreateRequest, error) {
	log.Info("preparing maas request")
	bundle, err := cert.CABundleFromMap(c.secret.Data)
	if err != nil {
		return nil, err
	}
	var userdata string
	if c.isMaster {
		userdata, err = masterUserdata(c, bundle)
	} else {
		userdata, err = workerUserdata(c, bundle)
	}
	if err != nil {
		return nil, err
	}
	// TODO: ProviderID should be unique. One way to ensure this is to generate
	// a UUID. Cf. k8s.io/apimachinery/pkg/util/uuid
	providerID := fmt.Sprintf("%s-%s", c.cluster.Name, c.machine.Name)
	distro := getImage(c.maasClient, "ubuntu-xenial", c.cluster.Spec.KubernetesVersion, c.machine.Spec.InstanceType)
	if distro == "" {
		return nil, errors.New("image does not exist")
	}
	return &maas.CreateRequest{
		ProviderID:   providerID,
		Distro:       distro,
		Userdata:     userdata,
		InstanceType: c.machine.Spec.InstanceType,
	}, nil
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
 - [ sh, -c, "tar xf /etc/kubernetes/pki/certs.tar -C /etc/kubernetes/pki" ]
 - [ sh, -c, "kubeadm init --node-name {{ .Name }}  --config /var/tmp/masterconfig.yaml" ]
 - [ sh, -c, "kubectl --kubeconfig /etc/kubernetes/admin.conf apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml" ]

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

// doMaasCreate returns the ip addr of the created instance or an error. It also
// updates the status of the machine object with the maas nodes information. If
// any steps fail the maas node will be released and it is safe to try again. If
// the systemId of the machine is already set then we return without taking any
// actions.
func doMaasCreate(c *creator) (string, error) {
	log.Info("calling create on maas")
	if c.machine.Status.SystemId != "" {
		log.Info("machine already allocated")
		return c.machine.Status.SshConfig.Host, nil
	}
	createResponse, err := c.maasClient.Create(context.Background(), c.createRequest)
	if err != nil {
		return "", err
	}

	if len(createResponse.IPAddresses) == 0 && createResponse.IPAddresses[0] != "" {
		log.Info("machine ip is nil, releasing", "maas create response", createResponse)
		err = c.maasClient.Delete(
			context.Background(),
			&maas.DeleteRequest{
				ProviderID: createResponse.ProviderID,
				SystemID:   createResponse.SystemID,
			},
		)
		if err != nil {
			return "", err
		}
		return "", errors.New("no ip address returned from maas")
	}
	c.machine.Status.SystemId = createResponse.SystemID
	c.machine.Status.SshConfig.Host = createResponse.IPAddresses[0]
	c.machine.Status.KubernetesVersion = c.cluster.Spec.KubernetesVersion
	err = c.k8sClient.Update(context.Background(), c.machine)
	if err != nil {
		delErr := c.maasClient.Delete(
			context.Background(),
			&maas.DeleteRequest{
				ProviderID: createResponse.ProviderID,
				SystemID:   createResponse.SystemID,
			},
		)
		if delErr != nil {
			innerErr := errors.Wrap(delErr, "could not delete machine").Error()
			return "", errors.Wrap(err, innerErr)
		}
		return "", err
	}
	return createResponse.IPAddresses[0], nil
}

func createKubeconfig(c *creator) error {
	log.Info("creating kubeconfig")
	bundle, err := cert.CABundleFromMap(c.secret.Data)
	if err != nil {
		return err
	}

	log.Info("create kubeconfig")
	kubeconfig, err := bundle.Kubeconfig(c.cluster.Name, "https://"+c.host+":6443")
	if err != nil {
		return err
	}

	log.Info("add kubeconfig to cluster-private-key secret")
	c.secret.Data[corev1.ServiceAccountKubeconfigKey] = kubeconfig
	return c.k8sClient.Update(context.Background(), c.secret)
}

func updateMachine(c *creator) error {
	// Add the finalizer
	if !util.ContainsString(c.machine.Finalizers, clusterv1alpha1.MachineFinalizer) {
		log.Info("adding finalizer to machine")
		c.machine.Finalizers = append(c.machine.Finalizers, clusterv1alpha1.MachineFinalizer)
	}

	log.Info("update machine status to ready")
	// update status to "creating"
	c.machine.Status.Phase = common.ReadyMachinePhase
	// Check if machine object has existing annotations
	if c.machine.ObjectMeta.Annotations == nil {
		c.machine.ObjectMeta.Annotations = map[string]string{}
	}

	return c.k8sClient.Update(context.Background(), c.machine)
}

func updateCluster(c *creator) error {
	log.Info("updating cluster")
	log.Info("updating cluster api endpoint")

	// TODO (apo): we may need to be smarter about adding the port to the host
	c.cluster.Status.APIEndpoint = c.machine.Status.SshConfig.Host + ":6443"
	return c.k8sClient.Update(context.Background(), c.cluster)
}

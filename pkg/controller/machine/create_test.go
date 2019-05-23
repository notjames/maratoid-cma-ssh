package machine

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func Test_getExistingToken(t *testing.T) {
	emptyList := func(options metav1.ListOptions) (*corev1.SecretList, error) {
		return &corev1.SecretList{Items: []corev1.Secret{}}, nil
	}
	notFoundErr := func(metav1.ListOptions) (*corev1.SecretList, error) {
		return nil, errors.NewNotFound(schema.GroupResource{Group: "core", Resource: "secrets"}, "")
	}
	nonNilErr := func(metav1.ListOptions) (*corev1.SecretList, error) {
		return nil, fmt.Errorf("something bad happened")
	}
	secretWithFutureExpiration := func(options metav1.ListOptions) (*corev1.SecretList, error) {
		return &corev1.SecretList{
			Items: []corev1.Secret{
				{
					Data: map[string][]byte{
						"expiration":   []byte(time.Now().Add(time.Hour).Format(time.RFC3339)),
						"token-id":     []byte("andrew"),
						"token-secret": []byte("bikestoworkoften"),
					},
				},
			},
		}, nil
	}
	secretWithPastExpiration := func(options metav1.ListOptions) (*corev1.SecretList, error) {
		return &corev1.SecretList{
			Items: []corev1.Secret{
				{
					Data: map[string][]byte{
						"expiration": []byte(time.Now().Add(-time.Hour).Format(time.RFC3339)),
					},
				},
			},
		}, nil
	}

	tests := []struct {
		name     string
		secretFn func(metav1.ListOptions) (*corev1.SecretList, error)
		want     string
		wantErr  bool
	}{
		{name: "empty list", secretFn: emptyList, want: "", wantErr: false},
		{name: "not found", secretFn: notFoundErr, want: "", wantErr: false},
		{name: "non nil err", secretFn: nonNilErr, want: "", wantErr: true},
		{name: "past expiration", secretFn: secretWithPastExpiration, want: "", wantErr: false},
		{name: "found secret", secretFn: secretWithFutureExpiration, want: "andrew.bikestoworkoften", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getExistingToken(tt.secretFn)
			if (err != nil) != tt.wantErr {
				t.Errorf("getExistingToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getExistingToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

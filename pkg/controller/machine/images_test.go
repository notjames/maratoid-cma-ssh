package machine

import (
	"reflect"
	"testing"
)

func Test_parse(t *testing.T) {
	standardImage := func(raw string) image {
		return image{os: "ubuntu", k8sVersion: "1.13.5", instanceType: "standard", raw: raw}
	}
	gpuImage := func(raw string) image {
		return image{os: "ubuntu", k8sVersion: "1.13.5", instanceType: "gpu", raw: raw}
	}

	tests := []struct {
		name    string
		raw     string
		wantImg image
		wantOk  bool
	}{
		{name: "empty string", raw: "", wantImg: image{}, wantOk: false},
		{name: "standard", raw: "os=ubuntu,k8s=1.13.5,standard", wantImg: standardImage("os=ubuntu,k8s=1.13.5,standard"), wantOk: true},
		{name: "gpu", raw: "os=ubuntu,k8s=1.13.5,gpu", wantImg: gpuImage("os=ubuntu,k8s=1.13.5,gpu"), wantOk: true},
		{name: "missing instance type", raw: "os=ubuntu,k8s=1.13.5", wantImg: image{}, wantOk: false},
		{name: "missing os", raw: "k8s=1.13.5,standard", wantImg: image{}, wantOk: false},
		{name: "missing k8s version", raw: "os=ubuntu,standard", wantImg: image{}, wantOk: false},
		{name: "out of order", raw: "standard,os=ubuntu,k8s=1.13.5", wantImg: standardImage("standard,os=ubuntu,k8s=1.13.5"), wantOk: true},
		{name: "empty i", raw: "standard,,os=ubuntu,k8s=1.13.5", wantImg: standardImage("standard,,os=ubuntu,k8s=1.13.5"), wantOk: true},
		{name: "unused i", raw: "os=ubuntu,andrew=cool,k8s=1.13.5,standard", wantImg: standardImage("os=ubuntu,andrew=cool,k8s=1.13.5,standard"), wantOk: true},
		{name: "repeated key", raw: "os=fedora,os=ubuntu,k8s=1.12.5,k8s=1.13.5,gpu,standard", wantImg: standardImage("os=fedora,os=ubuntu,k8s=1.12.5,k8s=1.13.5,gpu,standard"), wantOk: true},
		{name: "multiple =", raw: "====", wantImg: image{}, wantOk: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := parse(tt.raw)
			if !reflect.DeepEqual(got, tt.wantImg) {
				t.Errorf("parse() got = %v, wantImg %v", got, tt.wantImg)
			}
			if got1 != tt.wantOk {
				t.Errorf("parse() got1 = %v, wantImg %v", got1, tt.wantOk)
			}
		})
	}
}

func Test_image_in(t *testing.T) {
	standard, _ := parse("os=ubuntu,k8s=1.13.5,standard")
	tests := []struct {
		name   string
		i      image
		images []string
		want   bool
	}{
		{name: "empty slice", i: standard, images: []string{}, want: false},
		{name: "not findIn", i: standard, images: []string{"os=ubuntu,k8s=1.13.5,gpu"}, want: false},
		{name: "nil slice", i: standard, images: nil, want: false},
		{name: "findIn", i: standard, images: []string{"", "os=ubuntu,k8s=1.13.5,standard", "os=ubuntu,k8s=1.13.5,gpu"}, want: true},
		{name: "different instance type", i: standard, images: []string{"os=ubuntu,k8s=1.13.5,gpu"}, want: false},
		{name: "multiple matches", i: standard, images: []string{"os=ubuntu,k8s=1.13.5,gpu", "os=ubuntu,k8s=1.13.5,standard", "os=ubuntu,k8s=1.13.5,standard"}, want: true},
		{name: "bad image", i: image{}, images: []string{"os=ubuntu,k8s=1.13.5,standard", "os=ubuntu,k8s=1.13.5,gpu", ""}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &image{
				os:           tt.i.os,
				k8sVersion:   tt.i.k8sVersion,
				instanceType: tt.i.instanceType,
				raw:          tt.i.raw,
			}
			if got := i.findIn(tt.images); got != tt.want {
				t.Errorf("image.findIn() = %v, want %v", got, tt.want)
			}
		})
	}
}

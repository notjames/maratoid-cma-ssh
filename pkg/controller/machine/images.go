package machine

import (
	"strings"

	"github.com/samsung-cnct/cma-ssh/pkg/maas"
)

type image struct {
	os           string
	k8sVersion   string
	instanceType string
	raw          string
}

func (i *image) set(key, value string) {
	switch key {
	case "os":
		i.os = value
	case "k8s":
		i.k8sVersion = value
	case "standard":
		i.instanceType = key
	case "gpu":
		i.instanceType = key
	}
}

// parse decodes a string into an image and returns if it was successful.
func parse(raw string) (image, bool) {
	var i image
	i.raw = raw
	fields := strings.Split(raw, ",")
	for _, field := range fields {
		keyValue := strings.Split(field, "=")
		var key, value string
		switch len(keyValue) {
		case 1:
			key = keyValue[0]
		case 2:
			key = keyValue[0]
			value = keyValue[1]
		default:
			continue
		}
		i.set(key, value)
	}
	if i.os == "" || i.k8sVersion == "" || i.instanceType == "" {
		return image{}, false
	}
	return i, true
}

func (i *image) findIn(images []string) bool {
	if i.os == "" || i.k8sVersion == "" || i.instanceType == "" {
		return false
	}
	for _, raw := range images {
		img, ok := parse(raw)
		if !ok {
			continue
		}
		if img.os == i.os && img.k8sVersion == i.k8sVersion && img.instanceType == i.instanceType {
			i.raw = img.raw
			return true
		}
	}
	return false
}

// getImage checks if maas contains an image that matches the user
// specification and returns it.
func getImage(c maas.Client, osVersion, k8sVersion, instanceType string) string {
	i := image{
		os:           osVersion,
		k8sVersion:   k8sVersion,
		instanceType: instanceType,
	}
	if i.findIn(c.Images()) {
		return i.raw
	}
	return ""
}

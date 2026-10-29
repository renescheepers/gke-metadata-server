// Copyright 2025 Matheus Pimenta.
// SPDX-License-Identifier: AGPL-3.0

package routing

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/matheuscscp/gke-metadata-server/api"
	"github.com/matheuscscp/gke-metadata-server/internal/loopback"
	"github.com/matheuscscp/gke-metadata-server/internal/redirect"

	corev1 "k8s.io/api/core/v1"
)

var cgroupRoot = "/sys/fs/cgroup" // var so tests can override it

// LoadAndAttach looks up the routing mode from the Node's annotations
// or labels and loads and attaches the routing mechanism accordingly.
// In eBPF mode it also returns the cgroup path the redirect is attached to.
func LoadAndAttach(node *corev1.Node, emulatorIP netip.Addr, emulatorPort int) (string, string, func() error, error) {
	var loadAndAttach func() (func() error, error)
	var cgroupPath string

	mode := getMode(node)
	switch mode {
	case api.RoutingModeBPF:
		var err error
		if cgroupPath, err = getCgroupPath(node); err != nil {
			return "", "", nil, err
		}
		loadAndAttach = redirect.LoadAndAttach(emulatorIP, emulatorPort, cgroupPath)
	case api.RoutingModeLoopback:
		loadAndAttach = loopback.LoadAndAttach
	case api.RoutingModeNone:
		loadAndAttach = func() (func() error, error) {
			return func() error { return nil }, nil
		}
	default:
		return "", "", nil, fmt.Errorf("invalid routing mode: %s", mode)
	}

	close, err := loadAndAttach()
	if err != nil {
		return "", "", nil, err
	}
	return mode, cgroupPath, close, nil
}

func getMode(node *corev1.Node) string {
	if m := node.Annotations[api.AnnotationRoutingMode]; m != "" {
		return m
	}
	if m := node.Labels[api.AnnotationRoutingMode]; m != "" {
		return m
	}
	return api.RoutingModeDefault
}

func getCgroupPath(node *corev1.Node) (string, error) {
	v := node.Annotations[api.AnnotationCgroupPath]
	if v == "" {
		v = node.Labels[api.AnnotationCgroupPath]
	}
	if v == "" {
		return cgroupRoot, nil
	}
	p := filepath.Clean(v)
	// Label values can't contain "/", so a relative value is taken relative to the cgroup root.
	if !filepath.IsAbs(p) {
		p = filepath.Join(cgroupRoot, p)
	}
	if p != cgroupRoot && !strings.HasPrefix(p, cgroupRoot+"/") {
		return "", fmt.Errorf("invalid %s %q: must be a directory under %s", api.AnnotationCgroupPath, v, cgroupRoot)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", api.AnnotationCgroupPath, v, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("invalid %s %q: %s is not a directory", api.AnnotationCgroupPath, v, p)
	}
	return p, nil
}

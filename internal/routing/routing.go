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
	"github.com/matheuscscp/gke-metadata-server/internal/attestation"
	"github.com/matheuscscp/gke-metadata-server/internal/loopback"
	"github.com/matheuscscp/gke-metadata-server/internal/redirect"

	corev1 "k8s.io/api/core/v1"
)

var selfCgroupDir = redirect.SelfCgroupDir

// LoadAndAttach looks up the routing mode from the Node's annotations
// or labels and loads and attaches the routing mechanism accordingly.
// In eBPF mode it also returns the cgroup path the redirect is attached to.
func LoadAndAttach(node *corev1.Node, emulatorIP netip.Addr, emulatorPort int) (string, string, func() error, error) {
	var loadAndAttach func() (func() error, error)

	mode, cgroupPath, err := getMode(node)
	if err != nil {
		return mode, "", nil, err
	}
	switch mode {
	case api.RoutingModeBPF:
		loadAndAttach = redirect.LoadAndAttach(emulatorIP, emulatorPort, cgroupPath)
	case api.RoutingModeLoopback:
		loadAndAttach = loopback.LoadAndAttach
	case api.RoutingModeNone:
		loadAndAttach = func() (func() error, error) {
			return func() error { return nil }, nil
		}
	default:
		return mode, "", nil, fmt.Errorf("invalid routing mode: %s", mode)
	}

	close, err := loadAndAttach()
	if err != nil {
		return mode, "", nil, err
	}
	return mode, cgroupPath, close, nil
}

func getMode(node *corev1.Node) (mode, cgroupPath string, err error) {
	mode = node.Annotations[api.AnnotationRoutingMode]
	if mode == "" {
		mode = node.Labels[api.AnnotationRoutingMode]
	}
	if mode == "" {
		mode = api.RoutingModeDefault
	}
	switch mode {
	case api.RoutingModeBPF:
		cgroupPath, err = getCgroupPath(node)
		return mode, cgroupPath, err
	case api.RoutingModeLoopback, api.RoutingModeNone:
		if node.Annotations[api.AnnotationCgroupPath] != "" || node.Labels[api.AnnotationCgroupPath] != "" {
			return mode, "", fmt.Errorf("%s is only supported in the %s routing mode, not %s",
				api.AnnotationCgroupPath, api.RoutingModeBPF, mode)
		}
	}
	return mode, "", nil
}

func getCgroupPath(node *corev1.Node) (string, error) {
	v := node.Annotations[api.AnnotationCgroupPath]
	if v == "" {
		v = node.Labels[api.AnnotationCgroupPath]
	}
	if v == "" {
		return attestation.CgroupV2Mount, nil
	}
	p := filepath.Clean(v)
	// Label values can't contain "/", so a relative value is taken relative to the cgroup root.
	if !filepath.IsAbs(p) {
		p = filepath.Join(attestation.CgroupV2Mount, p)
	}
	if !isUnder(p, attestation.CgroupV2Mount) {
		return "", fmt.Errorf("invalid %s %q: must be a directory under %s", api.AnnotationCgroupPath, v, attestation.CgroupV2Mount)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", api.AnnotationCgroupPath, v, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("invalid %s %q: %s is not a directory", api.AnnotationCgroupPath, v, p)
	}
	self, err := selfCgroupDir()
	if err != nil {
		return "", fmt.Errorf("error resolving the emulator's own cgroup: %w", err)
	}
	if !isUnder(self, p) {
		return "", fmt.Errorf("invalid %s %q: must contain the emulator's own Pod cgroup %s", api.AnnotationCgroupPath, v, self)
	}
	return p, nil
}

func isUnder(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

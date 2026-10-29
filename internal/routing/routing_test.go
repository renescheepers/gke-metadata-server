// Copyright 2026 Matheus Pimenta.
// SPDX-License-Identifier: AGPL-3.0

package routing

import (
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/matheuscscp/gke-metadata-server/api"
	"github.com/matheuscscp/gke-metadata-server/internal/attestation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fakeCgroupRoot(t *testing.T) (root, pods string) {
	t.Helper()
	root = t.TempDir()
	pods = filepath.Join(root, "kubepods.slice")
	require.NoError(t, os.Mkdir(pods, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, "system.slice"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cgroup.procs"), nil, 0o644))

	oldMount, oldSelf := attestation.CgroupV2Mount, selfCgroupDir
	attestation.CgroupV2Mount = root
	selfCgroupDir = func() (string, error) {
		return filepath.Join(pods, "kubepods-besteffort.slice", "emulator.scope"), nil
	}
	t.Cleanup(func() {
		attestation.CgroupV2Mount, selfCgroupDir = oldMount, oldSelf
	})
	return root, pods
}

func newNode(annotations, labels map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Annotations: annotations,
		Labels:      labels,
	}}
}

func TestGetCgroupPath(t *testing.T) {
	root, pods := fakeCgroupRoot(t)

	for _, tt := range []struct {
		name        string
		annotations map[string]string
		labels      map[string]string
		want        string
		wantErr     string
		wantErrIs   error
	}{
		{
			name: "unset means the root",
			want: root,
		},
		{
			name:        "annotation",
			annotations: map[string]string{api.AnnotationCgroupPath: pods},
			want:        pods,
		},
		{
			name:   "label is relative to the root",
			labels: map[string]string{api.AnnotationCgroupPath: "kubepods.slice"},
			want:   pods,
		},
		{
			name:        "annotation wins over label",
			annotations: map[string]string{api.AnnotationCgroupPath: pods},
			labels:      map[string]string{api.AnnotationCgroupPath: "system.slice"},
			want:        pods,
		},
		{
			name:        "outside the root",
			annotations: map[string]string{api.AnnotationCgroupPath: "/etc"},
			wantErr:     "must be a directory under",
		},
		{
			name:        "relative path out of the root",
			annotations: map[string]string{api.AnnotationCgroupPath: "../etc"},
			wantErr:     "must be a directory under",
		},
		{
			name:        "missing directory",
			annotations: map[string]string{api.AnnotationCgroupPath: filepath.Join(root, "kubepods")},
			wantErrIs:   fs.ErrNotExist,
		},
		{
			name:        "not a directory",
			annotations: map[string]string{api.AnnotationCgroupPath: filepath.Join(root, "cgroup.procs")},
			wantErr:     "is not a directory",
		},
		{
			name:        "directory without the emulator's own Pod",
			annotations: map[string]string{api.AnnotationCgroupPath: filepath.Join(root, "system.slice")},
			wantErr:     "must contain the emulator's own Pod cgroup",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCgroupPath(newNode(tt.annotations, tt.labels))
			if tt.wantErrIs != nil {
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetMode(t *testing.T) {
	root, pods := fakeCgroupRoot(t)

	for _, tt := range []struct {
		name           string
		annotations    map[string]string
		labels         map[string]string
		wantMode       string
		wantCgroupPath string
		wantErr        string
	}{
		{
			name:           "default is eBPF on the root",
			wantMode:       api.RoutingModeBPF,
			wantCgroupPath: root,
		},
		{
			name:     "label",
			labels:   map[string]string{api.AnnotationRoutingMode: api.RoutingModeLoopback},
			wantMode: api.RoutingModeLoopback,
		},
		{
			name:        "annotation wins over label",
			annotations: map[string]string{api.AnnotationRoutingMode: api.RoutingModeNone},
			labels:      map[string]string{api.AnnotationRoutingMode: api.RoutingModeLoopback},
			wantMode:    api.RoutingModeNone,
		},
		{
			name:           "eBPF with cgroupPath",
			annotations:    map[string]string{api.AnnotationCgroupPath: pods},
			wantMode:       api.RoutingModeBPF,
			wantCgroupPath: pods,
		},
		{
			name:        "eBPF with an invalid cgroupPath",
			annotations: map[string]string{api.AnnotationCgroupPath: "/etc"},
			wantMode:    api.RoutingModeBPF,
			wantErr:     "must be a directory under",
		},
		{
			name: "cgroupPath annotation in Loopback mode",
			annotations: map[string]string{
				api.AnnotationRoutingMode: api.RoutingModeLoopback,
				api.AnnotationCgroupPath:  pods,
			},
			wantMode: api.RoutingModeLoopback,
			wantErr:  "is only supported in the eBPF routing mode",
		},
		{
			name: "cgroupPath label in None mode",
			labels: map[string]string{
				api.AnnotationRoutingMode: api.RoutingModeNone,
				api.AnnotationCgroupPath:  "kubepods.slice",
			},
			wantMode: api.RoutingModeNone,
			wantErr:  "is only supported in the eBPF routing mode",
		},
		{
			name: "invalid mode is left to LoadAndAttach",
			annotations: map[string]string{
				api.AnnotationRoutingMode: "ebpf",
				api.AnnotationCgroupPath:  pods,
			},
			wantMode: "ebpf",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mode, cgroupPath, err := getMode(newNode(tt.annotations, tt.labels))
			assert.Equal(t, tt.wantMode, mode)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCgroupPath, cgroupPath)
		})
	}
}

func TestLoadAndAttachInvalidMode(t *testing.T) {
	node := newNode(map[string]string{
		api.AnnotationRoutingMode: "ebpf",
		api.AnnotationCgroupPath:  "/sys/fs/cgroup/kubepods.slice",
	}, nil)

	mode, _, _, err := LoadAndAttach(node, netip.Addr{}, 0)
	assert.Equal(t, "ebpf", mode)
	assert.EqualError(t, err, "invalid routing mode: ebpf")
}

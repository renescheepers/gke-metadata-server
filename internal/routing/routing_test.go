// Copyright 2026 Matheus Pimenta.
// SPDX-License-Identifier: AGPL-3.0

package routing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/matheuscscp/gke-metadata-server/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetCgroupPath(t *testing.T) {
	root := t.TempDir()
	old := cgroupRoot
	cgroupRoot = root
	t.Cleanup(func() { cgroupRoot = old })

	pods := filepath.Join(root, "kubepods.slice")
	require.NoError(t, os.Mkdir(pods, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, "system.slice"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cgroup.procs"), nil, 0o644))

	for _, tt := range []struct {
		name        string
		annotations map[string]string
		labels      map[string]string
		want        string
		wantErr     string
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
			wantErr:     "no such file or directory",
		},
		{
			name:        "not a directory",
			annotations: map[string]string{api.AnnotationCgroupPath: filepath.Join(root, "cgroup.procs")},
			wantErr:     "is not a directory",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Annotations: tt.annotations,
				Labels:      tt.labels,
			}}
			got, err := getCgroupPath(node)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

package dtest

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/datawire/dlib/dexec"
	"github.com/datawire/dlib/dlog"
)

// requireDocker calls t.SkipNow() if we're running in CI and Docker isn't available.
func requireDocker(t *testing.T) {
	if os.Getenv("CI") == "" {
		// Always run when not in CI.
		return
	}
	docker, err := dexec.LookPath("docker")
	if docker == "" || err != nil {
		if runtime.GOOS == "linux" {
			t.Fatal("The CI setup is broken, it doesn't even have docker on Linux")
		}
		t.Log("Skipping because 'docker' is not installed")
		t.SkipNow()
	}
	if runtime.GOOS == "windows" {
		t.Log("Skipping because 'docker' is set to run Windows containers not Linux containers")
		t.SkipNow()
	}
}

func TestContainer(t *testing.T) {
	requireDocker(t)
	ctx := dlog.NewTestContext(t, false)
	WithMachineLock(ctx, func(ctx context.Context) {
		id, err := dockerUp(ctx, "dtest-test-tag", "nginx")
		require.NoError(t, err)

		running, err := dockerPs(ctx)
		require.NoError(t, err)
		assert.Contains(t, running, id)

		require.NoError(t, dockerKill(ctx, id))

		running, err = dockerPs(ctx)
		require.NoError(t, err)
		assert.NotContains(t, running, id)
	})
}

func TestCluster(t *testing.T) {
	requireDocker(t)
	for minor := range k3sImages {
		ver := KubeVersion{minor}
		t.Run(fmt.Sprintf("1.%d", minor), func(t *testing.T) {
			ctx := dlog.NewTestContext(t, false)
			WithMachineLock(ctx, func(ctx context.Context) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatal(r)
					}
				}()
				_, err := K3sDown(ctx)
				require.NoError(t, err)
				registry, err := DockerRegistry(ctx)
				require.NoError(t, err)
				os.Setenv("DTEST_REGISTRY", registry) // Prevent extra calls to dtest.RegistryUp() which may panic
				defer func() {
					_, err := RegistryDown(ctx)
					require.NoError(t, err)
				}()

				kubeconfig, err := KubeVersionConfig(ctx, ver)
				require.NoError(t, err)
				defer func() {
					_, err := K3sDown(ctx)
					require.NoError(t, err)
					assert.NoError(t, os.Remove(kubeconfig))
				}()
			})
		})
	}
}

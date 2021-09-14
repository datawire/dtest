package dtest

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

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
		id := dockerUp(ctx, "dtest-test-tag", "nginx")

		running := dockerPs(ctx)
		assert.Contains(t, running, id)

		dockerKill(ctx, id)

		running = dockerPs(ctx)
		assert.NotContains(t, running, id)
	})
}

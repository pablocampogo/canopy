package main

import (
	"strings"
	"testing"

	"github.com/canopy-network/canopy/cmd/rpc"
	"github.com/canopy-network/canopy/lib"
	"github.com/stretchr/testify/require"
)

// Validation itself is covered in lib; these cover argument handling.
func TestRun(t *testing.T) {
	t.Run("valid bare version", func(t *testing.T) {
		require.NoError(t, run([]string{"1.2.3"}))
	})
	t.Run("valid v-prefixed version", func(t *testing.T) {
		require.NoError(t, run([]string{"v1.2.3"}))
	})
	t.Run("invalid four-segment version", func(t *testing.T) {
		require.Error(t, run([]string{"1.0.4.5"}))
	})
	t.Run("empty version", func(t *testing.T) {
		require.Error(t, run([]string{""}))
	})
	t.Run("no arguments", func(t *testing.T) {
		require.Error(t, run(nil))
	})
	t.Run("too many arguments", func(t *testing.T) {
		require.Error(t, run([]string{"1.0.0", "2.0.0"}))
	})
}

// Strip only the optional "v" (build metadata like "+beta" is significant) so
// the test derives the matching release version straight from the server constant.
func serverReleaseVersion(t *testing.T) string {
	t.Helper()
	v := strings.TrimPrefix(rpc.SoftwareVersion, "v")
	require.True(t, lib.IsValidVersion(v))
	return v
}

func TestRunCheckServerVersion(t *testing.T) {
	version := serverReleaseVersion(t)
	t.Run("matching bare version", func(t *testing.T) {
		require.NoError(t, run([]string{"--check-server-version", version}))
	})
	t.Run("matching v-prefixed version", func(t *testing.T) {
		require.NoError(t, run([]string{"--check-server-version", "v" + version}))
	})
	t.Run("matches server constant directly", func(t *testing.T) {
		require.NoError(t, run([]string{"--check-server-version", rpc.SoftwareVersion}))
	})
	t.Run("mismatched version", func(t *testing.T) {
		require.Error(t, run([]string{"--check-server-version", "99.99.99"}))
	})
	t.Run("mismatched build metadata", func(t *testing.T) {
		if !strings.Contains(rpc.SoftwareVersion, "+") {
			t.Skip("server version has no build metadata to differ on")
		}
		base := version[:strings.IndexByte(version, '+')]
		require.Error(t, run([]string{"--check-server-version", base}))
	})
	t.Run("skips check when flag absent", func(t *testing.T) {
		require.NoError(t, run([]string{"99.99.99"}))
	})
}

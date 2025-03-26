package nftrace

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KernelVersionParser(t *testing.T) {
	testCases := []struct {
		inputVersion string
		wantVersion  KernelVersion
	}{
		{
			inputVersion: "5.15.1-130-generic",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 1},
		},
		{
			inputVersion: "5.15.1",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 1},
		},
		{
			inputVersion: "5.15.1-060700-generic",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 1},
		},
		{
			inputVersion: "5.15",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			inputVersion: "5.15.0",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			inputVersion: "5.15-1",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			inputVersion: "5.15-rc8",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			inputVersion: "5.15.rc3",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 0},
		},
		{
			inputVersion: "Linux5.15.1",
			wantVersion:  KernelVersion{Major: 5, Minor: 15, Patch: 1},
		},
	}
	for _, tc := range testCases {
		gotVersion, err := parseKernelVersion(tc.inputVersion)
		require.NoError(t, err)
		require.Equal(t, tc.wantVersion, gotVersion)
	}
}

func Test_KernelVersionCompare(t *testing.T) {
	testCases := []struct {
		currentVersion KernelVersion
		cmpVersion     KernelVersion
		isGreater      bool
	}{
		{
			currentVersion: KernelVersion{5, 15, 0},
			cmpVersion:     KernelVersion{5, 8, 0},
			isGreater:      true,
		},
		{
			currentVersion: KernelVersion{5, 15, 0},
			cmpVersion:     KernelVersion{5, 15, 0},
			isGreater:      true,
		},
		{
			currentVersion: KernelVersion{5, 15, 0},
			cmpVersion:     KernelVersion{5, 15, 1},
		},
		{
			currentVersion: KernelVersion{5, 15, 0},
			cmpVersion:     KernelVersion{5, 16, 0},
		},
		{
			currentVersion: KernelVersion{5, 15, 0},
			cmpVersion:     KernelVersion{6, 15, 0},
		},
	}
	for _, tc := range testCases {
		require.Equal(t, tc.isGreater, tc.currentVersion.IsAtLeast(tc.cmpVersion))
	}
}

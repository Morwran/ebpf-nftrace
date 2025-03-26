package nftrace

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_KernelModules(t *testing.T) {
	testCases := []struct {
		name     string
		filePath string
		isErr    bool
	}{
		{
			name:     "kernel modules exist",
			filePath: "./test-data/modules-exist.txt",
		},
		{
			name:     "kernel modules missing",
			filePath: "./test-data/modules-missing.txt",
			isErr:    true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kernelModulesFile = tc.filePath
			err := checkKernelModules(requiredKernelModules...)
			if tc.isErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

package bytes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ByteEncoder(t *testing.T) {

	testCases := []struct {
		name     string
		expected any
		encode   func() any
	}{
		{
			name:     "uint64(0)",
			expected: uint64(0),
			encode: func() any {
				return RawBytes([]byte{0}).Uint64()
			},
		},
		{
			name:     "Empty String",
			expected: "",
			encode: func() any {
				return RawBytes([]byte{0}).String()
			},
		},
		{
			name:     "Empty Text base 10",
			expected: "0",
			encode: func() any {
				return RawBytes([]byte{0}).Text(10)
			},
		},
		{
			name:     "NOt empty String",
			expected: "test",
			encode: func() any {
				return RawBytes([]byte("test")).String()
			},
		},

		{
			name:     "interface lo to String",
			expected: "lo",
			encode: func() any {
				return RawBytes([]byte{108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}).String()
			},
		},
		{
			name:     "27759 to String",
			expected: "27759",
			encode: func() any {
				return RawBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 111}).String()
			},
		},
		{
			name:     "27759 to Uint64",
			expected: uint64(27759),
			encode: func() any {
				return RawBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 111}).Uint64()
			},
		},
		{
			name:     "27759 to Text base 10",
			expected: "27759",
			encode: func() any {
				return RawBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 111}).Text(10)
			},
		},
		{
			name:     "6 to String",
			expected: "6",
			encode: func() any {
				return RawBytes([]byte{6}).String()
			},
		},
		{
			name:     "P to string",
			expected: "P",
			encode: func() any {
				return RawBytes([]byte{80}).String()
			},
		},
		{
			name:     "80 to Text base 10",
			expected: "80",
			encode: func() any {
				return RawBytes([]byte{80}).Text(10)
			},
		},
		{
			name:     "80 to Uint64",
			expected: uint64(80),
			encode: func() any {
				return RawBytes([]byte{80}).Uint64()
			},
		},
		{
			name:     "to ip String",
			expected: "93.184.216.34",
			encode: func() any {
				return RawBytes([]byte{93, 184, 216, 34}).Ip().String()
			},
		},
		{
			name:     "to CIDR String",
			expected: "10.0.0.0/8",
			encode: func() any {
				return RawBytes([]byte{10}).CIDR().String()
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.encode())
		})
	}
}

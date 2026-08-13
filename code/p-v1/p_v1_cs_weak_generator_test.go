package elgamal

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tivi.io/core/crypto"
	x_509 "tivi.io/core/crypto/x509"
)

func TestPV1CSAcceptsWeakGeneratorParameters(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{name: "identity", fixture: "weak-g1-y1-public.pem"},
		{name: "non_qr", fixture: "weak-nonqr-y1-public.pem"},
	}

	unmarshaller := x_509.NewUnmarshaller[crypto.EncryptionKey](NewX509Unmarshaller())
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params, pkey, err := unmarshaller.Unmarshal(readPV1Fixture(t, tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if pkey == nil {
				t.Fatal("nil public key")
			}
			if params.Group().Name() != "RFC3526ModPGroup3072" {
				t.FailNow()
			}
			t.Logf("PASS: CS accepted the %s weak-generator parameters", tc.name)
		})
	}
}

func TestPV1CSAcceptsWeakGeneratorCiphertext(t *testing.T) {
	unmarshaller := x_509.NewUnmarshaller[crypto.EncryptionKey](NewX509Unmarshaller())
	params, _, err := unmarshaller.Unmarshal(readPV1Fixture(t, "weak-g1-y1-public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(readPV1Fixture(t, "weak-g1-y1-ciphertext.b64"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = UnmarshalCiphertext(params.Group(), ciphertext); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS: CS accepted the ciphertext under the identity-generator parameters")
}

func readPV1Fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(os.Getenv("IVXV_POCROOT"), "p-v1", name))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return data
}

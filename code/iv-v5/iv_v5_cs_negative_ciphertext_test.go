package elgamal

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tivi.io/core/math/group"
	_ "tivi.io/core/math/group/all"
)

const ivv5ModP3072Group = "RFC3526ModPGroup3072"

func TestIVV5CSAcceptsNegativeASN1Ciphertext(t *testing.T) {
	g, err := group.Get(ivv5ModP3072Group)
	base64Ciphertext, err := os.ReadFile(locateIVV5Fixture(t))
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(base64Ciphertext)))
	if _, err = UnmarshalCiphertext(g, ciphertext); err != nil {
		t.Fatalf("CS rejected negative ASN.1 ciphertext: %v", err)
	}
	t.Log("PASS: CS accepted the negative ASN.1 ciphertext")
}

func locateIVV5Fixture(t *testing.T) string {
	t.Helper()
	root := os.Getenv("IVXV_POCROOT")
	return filepath.Join(root, "iv-v5", "negative_modp3072_ciphertext.b64")
}

package rxcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Vecteur de référence produit par l'émetteur Python (PyNaCl / libsodium
// crypto_secretstream_xchacha20poly1305) : voir testdata/testnet.zip.enc.
// Clé connue 00..1f, clair = "Bonjour, ceci est un vecteur de test de
// réversibilité. " répété 5000 fois (285000 octets).
const (
	tvKeyHex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	tvPlainSHA = "0c58734f1db842d0c4ed401141dfb0b9afdd0edabab45eb88d7aad1c20214b1e"
	tvPlainLen = 285000
)

// TestDecryptVector vérifie la conformité octet-à-octet avec libsodium en
// déchiffrant un fichier chiffré par l'émetteur Python.
func TestDecryptVector(t *testing.T) {
	key, err := hex.DecodeString(tvKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "plain.bin")
	net, err := Decrypt("testdata/testnet.zip.enc", out, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if net != "testnet" {
		t.Errorf("network = %q, attendu \"testnet\"", net)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != tvPlainLen {
		t.Errorf("longueur = %d, attendu %d", len(data), tvPlainLen)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != tvPlainSHA {
		t.Errorf("sha256 = %s, attendu %s", got, tvPlainSHA)
	}
}

// Fixture MONO-CHUNK avec un clair non aligné sur 16 (300 o) : couvre le
// « quirk » de bourrage du message de libsodium (pad = mlen % 16), qui diffère
// de l'alignement standard. Régression du bug corrigé.
const (
	scKeyHex   = "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a"
	scPlainSHA = "04773f8726c81cafcfa1a09a82664b98b00d2021031a1715bca1154f2dad3472"
	scPlainLen = 300
)

func TestDecryptSingleChunkUnaligned(t *testing.T) {
	key, _ := hex.DecodeString(scKeyHex)
	out := filepath.Join(t.TempDir(), "sc.bin")
	if _, err := Decrypt("testdata/singlechunk.zip.enc", out, key); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != scPlainLen {
		t.Errorf("longueur = %d, attendu %d", len(data), scPlainLen)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != scPlainSHA {
		t.Errorf("sha256 = %s, attendu %s", got, scPlainSHA)
	}
}

// TestWrongKeyFails : une mauvaise clé doit échouer (auth), sans produire de
// sortie.
func TestWrongKeyFails(t *testing.T) {
	key := make([]byte, 32) // clé nulle -> mauvaise
	out := filepath.Join(t.TempDir(), "plain.bin")
	if _, err := Decrypt("testdata/testnet.zip.enc", out, key); err == nil {
		t.Fatal("attendu: échec avec une mauvaise clé")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("le fichier de sortie ne devrait pas exister après échec")
	}
}

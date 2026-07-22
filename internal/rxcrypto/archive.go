package rxcrypto

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// magic : en-tête de fichier des archives chiffrées.
var magic = []byte("RXENC1\n")

// KitFiles regroupe les trois fichiers attendus dans le dossier source.
type KitFiles struct {
	Dir     string
	Network string
	EncPath string
	SigPath string
	PubPath string
}

// DetectKit repère, dans dir, l'unique `<network>.zip.enc` et en déduit les
// chemins de sa signature et de la clé publique.
func DetectKit(dir string) (*KitFiles, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var encs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".zip.enc") {
			encs = append(encs, e.Name())
		}
	}
	if len(encs) == 0 {
		return nil, errors.New("aucun fichier .zip.enc trouvé dans ce dossier")
	}
	if len(encs) > 1 {
		return nil, fmt.Errorf("plusieurs fichiers .zip.enc trouvés (%d) — gardez un seul réseau par dossier", len(encs))
	}
	enc := encs[0]
	network := strings.TrimSuffix(enc, ".zip.enc")
	return &KitFiles{
		Dir:     dir,
		Network: network,
		EncPath: filepath.Join(dir, enc),
		SigPath: filepath.Join(dir, enc+".sig"),
		PubPath: filepath.Join(dir, network+".sign.pub"),
	}, nil
}

// Missing renvoie la liste des fichiers requis absents.
func (k *KitFiles) Missing() []string {
	var m []string
	for _, p := range []string{k.EncPath, k.SigPath, k.PubPath} {
		if _, err := os.Stat(p); err != nil {
			m = append(m, filepath.Base(p))
		}
	}
	return m
}

// LoadPublicKey lit la clé publique Ed25519 (hex) et renvoie aussi son
// empreinte courte (sha256(pub)[:8] en hex, 16 caractères), comme l'émetteur.
func LoadPublicKey(pubPath string) (ed25519.PublicKey, string, error) {
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, "", err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, "", fmt.Errorf("clé publique illisible : %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("clé publique de taille invalide (%d octets)", len(b))
	}
	fp := sha256.Sum256(b)
	return ed25519.PublicKey(b), hex.EncodeToString(fp[:8]), nil
}

// VerifySignature vérifie la signature Ed25519 détachée (sur SHA-512 du .enc).
func VerifySignature(encPath, sigPath string, pub ed25519.PublicKey) error {
	dig, err := fileSHA512(encPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature de taille invalide (%d octets)", len(sig))
	}
	if !ed25519.Verify(pub, dig, sig) {
		return errors.New("signature INVALIDE — origine non prouvée, ne pas utiliser ce fichier")
	}
	return nil
}

func fileSHA512(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ParseKey décode la clé de déchiffrement K_i (hex, 32 octets).
func ParseKey(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("clé invalide (attendu : hexadécimal)")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("clé de taille invalide (%d octets, attendu 32)", len(b))
	}
	return b, nil
}

type meta struct {
	Network string `json:"network"`
}

// Decrypt lit l'archive chiffrée encPath et écrit le clair dans outPath.
// Renvoie le nom de réseau lu dans l'en-tête. En cas d'échec, outPath est
// supprimé.
func Decrypt(encPath, outPath string, key []byte) (network string, err error) {
	f, err := os.Open(encPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)

	hdr := make([]byte, len(magic))
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", errors.New("fichier illisible ou vide")
	}
	if !bytes.Equal(hdr, magic) {
		return "", errors.New("format invalide (ce n'est pas une archive .enc attendue)")
	}
	var l2 [2]byte
	if _, err := io.ReadFull(r, l2[:]); err != nil {
		return "", errors.New("en-tête tronqué")
	}
	hj := make([]byte, binary.BigEndian.Uint16(l2[:]))
	if _, err := io.ReadFull(r, hj); err != nil {
		return "", errors.New("en-tête tronqué")
	}
	var m meta
	_ = json.Unmarshal(hj, &m)

	ssHeader := make([]byte, ssHeaderBytes)
	if _, err := io.ReadFull(r, ssHeader); err != nil {
		return "", errors.New("en-tête secretstream tronqué")
	}
	st, err := newPullState(ssHeader, key)
	if err != nil {
		return "", err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	fail := func(e error) (string, error) {
		out.Close()
		os.Remove(outPath)
		return "", e
	}
	w := bufio.NewWriterSize(out, 1<<20)

	first := true
	var l4 [4]byte
	for {
		if _, err := io.ReadFull(r, l4[:]); err != nil {
			return fail(errors.New("flux tronqué : fichier incomplet ou altéré"))
		}
		ct := make([]byte, binary.BigEndian.Uint32(l4[:]))
		if _, err := io.ReadFull(r, ct); err != nil {
			return fail(errors.New("chunk tronqué : fichier incomplet ou altéré"))
		}
		var ad []byte
		if first {
			ad = hj
		}
		msg, tag, err := st.pull(ct, ad)
		if err != nil {
			return fail(err)
		}
		if _, err := w.Write(msg); err != nil {
			return fail(err)
		}
		first = false
		if tag == tagFinal {
			break
		}
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return m.Network, nil
}

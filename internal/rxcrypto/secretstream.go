// Package rxcrypto implémente, en Go pur (sans cgo), la vérification de
// signature (Ed25519 sur SHA-512) et le déchiffrement des archives de
// réversibilité « RXENC1 ».
//
// Le chiffrement d'origine (côté émetteur, en Python via PyNaCl) utilise la
// construction de flux authentifié de libsodium :
//
//	crypto_secretstream_xchacha20poly1305
//
// Ce fichier en réimplémente le côté « pull » (déchiffrement) à l'identique,
// à partir de golang.org/x/crypto/chacha20 (HChaCha20 + ChaCha20-IETF) et
// golang.org/x/crypto/poly1305. La conformité octet-à-octet avec libsodium est
// vérifiée par les tests (archive_test.go) contre un vecteur produit par
// l'émetteur Python.
package rxcrypto

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	ssHeaderBytes  = 24 // taille de l'en-tête secretstream
	ssKeyBytes     = 32
	ssABytes       = 17 // surcharge par chunk : 1 octet de tag + 16 octets de MAC
	ssInonceBytes  = 8
	ssCounterBytes = 4

	// Tags secretstream (identiques à libsodium).
	tagMessage byte = 0x00
	tagRekey   byte = 0x02
	tagFinal   byte = 0x03 // = PUSH|REKEY
)

// ssState reproduit l'état interne du secretstream : sous-clé + nonce composé
// d'un compteur de message (4 o, little-endian) suivi de l'« inonce » (8 o).
type ssState struct {
	k     [ssKeyBytes]byte
	nonce [12]byte // [counter(4, LE) || inonce(8)]
}

// newPullState initialise l'état de déchiffrement à partir de l'en-tête (24 o)
// et de la clé (32 o), comme crypto_secretstream_xchacha20poly1305_init_pull.
func newPullState(header, key []byte) (*ssState, error) {
	if len(header) != ssHeaderBytes {
		return nil, errors.New("en-tête secretstream de taille invalide")
	}
	if len(key) != ssKeyBytes {
		return nil, errors.New("clé de taille invalide")
	}
	sub, err := chacha20.HChaCha20(key, header[:16])
	if err != nil {
		return nil, err
	}
	s := &ssState{}
	copy(s.k[:], sub)
	s.counterReset()                 // nonce[0:4] = LE(1)
	copy(s.nonce[4:], header[16:24]) // inonce
	return s, nil
}

// counterReset remet le compteur de message à 1 (little-endian), inonce inchangé.
func (s *ssState) counterReset() {
	s.nonce[0], s.nonce[1], s.nonce[2], s.nonce[3] = 1, 0, 0, 0
}

// keystream renvoie n octets de flux ChaCha20-IETF (clé s.k, nonce s.nonce) à
// partir du bloc `counter`.
func (s *ssState) keystream(counter uint32, n int) ([]byte, error) {
	c, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		return nil, err
	}
	if counter != 0 {
		c.SetCounter(counter)
	}
	out := make([]byte, n)
	c.XORKeyStream(out, out) // XOR sur des zéros = flux brut
	return out, nil
}

// rekey applique la dérivation de clé de libsodium (déclenchée par TAG_REKEY /
// TAG_FINAL). Sans effet sur la sortie après le dernier chunk, mais reproduit
// fidèlement l'état.
func (s *ssState) rekey() error {
	var buf [ssKeyBytes + ssInonceBytes]byte // 40
	copy(buf[:ssKeyBytes], s.k[:])
	copy(buf[ssKeyBytes:], s.nonce[ssCounterBytes:])
	ks, err := s.keystream(0, len(buf))
	if err != nil {
		return err
	}
	for i := range buf {
		buf[i] ^= ks[i]
	}
	copy(s.k[:], buf[:ssKeyBytes])
	copy(s.nonce[ssCounterBytes:], buf[ssKeyBytes:])
	s.counterReset()
	return nil
}

// pull déchiffre et authentifie un chunk (c) avec ses données associées (ad,
// non nil uniquement pour le premier chunk). Renvoie le clair et le tag.
func (s *ssState) pull(c, ad []byte) (plain []byte, tag byte, err error) {
	if len(c) < ssABytes {
		return nil, 0, errors.New("chunk trop court")
	}
	mlen := len(c) - ssABytes

	// Bloc compteur 0 -> clé Poly1305 ; bloc compteur 1 -> bloc de tag.
	ks, err := s.keystream(0, 128)
	if err != nil {
		return nil, 0, err
	}
	var polyKey [32]byte
	copy(polyKey[:], ks[0:32])
	ks1 := ks[64:128]

	encTag := c[0]
	tag = encTag ^ ks1[0]

	// Bloc de tag tel qu'authentifié à l'émission : [encTag, ks1[1:64]].
	macTagBlock := make([]byte, 64)
	macTagBlock[0] = encTag
	copy(macTagBlock[1:], ks1[1:64])

	cipherMsg := c[1 : 1+mlen]
	gotMAC := c[1+mlen:]

	mac := poly1305.New(&polyKey)
	// AD : bourrage standard à 16 = (0x10 - adlen) & 0xf.
	macWriteADPadded(mac, ad)
	// Bloc de tag (64 o, déjà aligné).
	mac.Write(macTagBlock)
	// Message : bourrage « quirk » libsodium. Le code de référence est
	//   (0x10 - sizeof block + mlen) & 0xf
	// où, par précédence des opérateurs C, sizeof block (=64) n'est PAS entre
	// parenthèses : cela vaut (16 - 64 + mlen) & 0xf = mlen & 0xf (48 ≡ 0 [16]),
	// et NON l'alignement standard (0x10 - mlen) & 0xf.
	mac.Write(cipherMsg)
	if p := mlen % 16; p > 0 {
		var z [16]byte
		mac.Write(z[:p])
	}
	var slen [8]byte
	binary.LittleEndian.PutUint64(slen[:], uint64(len(ad)))
	mac.Write(slen[:])
	binary.LittleEndian.PutUint64(slen[:], uint64(64+mlen))
	mac.Write(slen[:])
	computed := mac.Sum(nil)

	if subtle.ConstantTimeCompare(computed, gotMAC) != 1 {
		return nil, 0, errors.New("authentification échouée (mauvaise clé ou fichier altéré)")
	}

	// Déchiffrement du message : bloc compteur 2.
	ks2, err := s.keystream(2, mlen)
	if err != nil {
		return nil, 0, err
	}
	plain = make([]byte, mlen)
	for i := 0; i < mlen; i++ {
		plain[i] = cipherMsg[i] ^ ks2[i]
	}

	// Chaînage du nonce : inonce ^= MAC[0:8], puis incrément du compteur.
	for i := 0; i < ssInonceBytes; i++ {
		s.nonce[ssCounterBytes+i] ^= computed[i]
	}
	incrementLE(s.nonce[:ssCounterBytes])

	if tag&tagRekey != 0 {
		if err := s.rekey(); err != nil {
			return nil, 0, err
		}
	}
	return plain, tag, nil
}

// macWriteADPadded écrit les données associées puis un bourrage de zéros
// jusqu'au multiple de 16 : (0x10 - adlen) & 0xf.
func macWriteADPadded(mac *poly1305.MAC, b []byte) {
	if len(b) > 0 {
		mac.Write(b)
	}
	if pad := (16 - len(b)%16) % 16; pad > 0 {
		var z [16]byte
		mac.Write(z[:pad])
	}
}

// incrementLE incrémente de 1 un entier little-endian sur place.
func incrementLE(b []byte) {
	var carry uint16 = 1
	for i := 0; i < len(b); i++ {
		carry += uint16(b[i])
		b[i] = byte(carry)
		carry >>= 8
	}
}

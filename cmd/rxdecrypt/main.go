// Command rxdecrypt : version ligne de commande (sans GUI) de la vérification
// de signature + déchiffrement d'une archive de réversibilité. Utile pour les
// utilisateurs avancés, les scripts et les tests.
//
//	rxdecrypt -src DOSSIER -key CLE_HEX -out DOSSIER_SORTIE
//	rxdecrypt -enc a.zip.enc -pub a.sign.pub -sig a.zip.enc.sig -key @cle.txt -out .
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CaporalDead/go_extract/internal/rxcrypto"
)

func readKey(v string) (string, error) {
	if strings.HasPrefix(v, "@") {
		b, err := os.ReadFile(v[1:])
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return v, nil
}

func main() {
	src := flag.String("src", "", "dossier source contenant <network>.zip.enc/.sig/.sign.pub")
	enc := flag.String("enc", "", "chemin de l'archive .zip.enc (au lieu de -src)")
	pub := flag.String("pub", "", "chemin de la clé publique .sign.pub (défaut: déduit)")
	sig := flag.String("sig", "", "chemin de la signature .sig (défaut: <enc>.sig)")
	key := flag.String("key", "", "clé K_i en hexadécimal, ou @fichier")
	out := flag.String("out", ".", "dossier (ou fichier) de sortie")
	skip := flag.Bool("skip-verify", false, "(déconseillé) ne pas vérifier la signature")
	flag.Parse()

	var kf *rxcrypto.KitFiles
	var err error
	if *src != "" {
		kf, err = rxcrypto.DetectKit(*src)
		if err != nil {
			fatal(err)
		}
	} else if *enc != "" {
		network := strings.TrimSuffix(filepath.Base(*enc), ".zip.enc")
		kf = &rxcrypto.KitFiles{Network: network, EncPath: *enc,
			SigPath: *enc + ".sig", PubPath: filepath.Join(filepath.Dir(*enc), network+".sign.pub")}
		if *sig != "" {
			kf.SigPath = *sig
		}
		if *pub != "" {
			kf.PubPath = *pub
		}
	} else {
		fatal(fmt.Errorf("préciser -src DOSSIER ou -enc FICHIER"))
	}

	if *key == "" {
		fatal(fmt.Errorf("préciser -key"))
	}
	keyHex, err := readKey(*key)
	if err != nil {
		fatal(err)
	}
	k, err := rxcrypto.ParseKey(keyHex)
	if err != nil {
		fatal(err)
	}

	if !*skip {
		vk, fp, err := rxcrypto.LoadPublicKey(kf.PubPath)
		if err != nil {
			fatal(err)
		}
		if err := rxcrypto.VerifySignature(kf.EncPath, kf.SigPath, vk); err != nil {
			fatal(err)
		}
		fmt.Printf("Signature VALIDE (empreinte %s).\n", fp)
	}

	outPath := *out
	if fi, err := os.Stat(*out); err == nil && fi.IsDir() {
		outPath = filepath.Join(*out, kf.Network+".zip")
	}
	net, err := rxcrypto.Decrypt(kf.EncPath, outPath, k)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Déchiffré -> %s   (network=%s)\n", outPath, net)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERREUR:", err)
	os.Exit(1)
}

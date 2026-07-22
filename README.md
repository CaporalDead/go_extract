# go_extract — Déchiffrement des archives de réversibilité

Application graphique **portable** (Windows / macOS / Linux) qui **vérifie la
signature d'origine** puis **déchiffre** une archive de réversibilité Monkey
Factory. Pensée pour des utilisateurs non techniques : pas de ligne de commande,
pas de Python à installer — un seul exécutable.

## Utilisation (application graphique)

1. Lancez `go_extract` (double-clic).
2. **Dossier des fichiers reçus** → choisissez le dossier qui contient les 3
   fichiers de votre réseau :
   - `<réseau>.zip.enc` (l'archive chiffrée),
   - `<réseau>.zip.enc.sig` (la signature),
   - `<réseau>.sign.pub` (la clé publique de vérification).
   L'application affiche le **réseau détecté** et l'**empreinte** de la clé
   publique — comparez-la à celle qui vous a été communiquée par un autre canal.
3. **Votre clé de déchiffrement** → collez la clé `K_i` (hexadécimal) reçue
   séparément, ou chargez-la depuis un fichier.
4. **Dossier de sortie** → où écrire l'archive en clair.
5. Cliquez **« Vérifier la signature + déchiffrer »**. En cas de succès, vous
   obtenez `<réseau>.zip`.

La signature est **toujours vérifiée avant** le déchiffrement : si elle est
invalide, rien n'est déchiffré (origine non prouvée).

## Version ligne de commande (optionnelle)

Un binaire `rxdecrypt` (dans `cmd/rxdecrypt`) offre la même opération sans GUI :

```
rxdecrypt -src DOSSIER            -key VOTRE_CLE_HEX     -out DOSSIER_SORTIE
rxdecrypt -enc a.zip.enc -pub a.sign.pub -sig a.zip.enc.sig -key @cle.txt -out .
```

## Sécurité / format

- Signature : **Ed25519** détachée sur le **SHA-512** du fichier `.enc`.
- Chiffrement : **libsodium `crypto_secretstream_xchacha20poly1305`** (flux
  authentifié, résistant à la troncature). Réimplémenté en **Go pur** (sans cgo)
  dans `internal/rxcrypto`, et **validé octet-à-octet** contre l'émetteur Python
  (PyNaCl) — voir les tests `go test ./internal/rxcrypto/...`.
- La clé `K_i` n'ouvre **que** l'archive du réseau concerné.

## Construire soi-même

Prérequis : Go 1.23+. Fyne utilise cgo (compilateur C requis).

```
# Linux : sudo apt-get install gcc libgl1-mesa-dev xorg-dev libxkbcommon-dev pkg-config
# macOS : Xcode Command Line Tools
# Windows : MinGW-w64 (gcc)

go test ./internal/rxcrypto/...     # valide la crypto
go build -o go_extract .            # (Windows: -ldflags -H=windowsgui)
```

## Binaires pré-construits (CI)

Le workflow GitHub Actions `.github/workflows/build.yml` construit les trois
plateformes (Linux, macOS, Windows) et publie les binaires en **artefacts** de
build. Onglet **Actions** du dépôt → dernière exécution → section *Artifacts*.

> ⚠️ Les binaires ne sont **pas signés** (signature de code = certificats
> payants). Au premier lancement :
> - **Windows** : SmartScreen → « Informations complémentaires » → « Exécuter
>   quand même ».
> - **macOS** : clic droit → « Ouvrir » → « Ouvrir » (contourne Gatekeeper).

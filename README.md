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

## Linux : AppImage (distributions standard)

Sur les distributions **standard (FHS)** — Ubuntu, Debian, Fedora, Arch… — le
plus simple est l'**AppImage**, un fichier unique :

```bash
chmod +x go_extract-linux-amd64.AppImage
./go_extract-linux-amd64.AppImage
```

> ⚠️ Comme **toute** AppImage d'application graphique, elle **n'embarque pas**
> `libGL` (OpenGL) : cette bibliothèque doit venir du système (elle est fournie
> par le pilote graphique, présent sur tout bureau Linux). Sur un système
> **non-FHS comme NixOS**, `libGL.so.1` n'est pas trouvé — voir la section NixOS.

Le **binaire nu** `go_extract-linux-amd64` est aussi fourni ; il nécessite les
mêmes bibliothèques OpenGL/X11. Si vous obtenez
`error while loading shared libraries: libGL.so.1` :

```
# Debian / Ubuntu
sudo apt-get install -y libgl1 libx11-6 libxcursor1 libxrandr2 libxinerama1 libxi6 libxxf86vm1
# Fedora
sudo dnf install -y mesa-libGL libX11 libXcursor libXrandr libXinerama libXi libXxf86vm
# Arch
sudo pacman -S --needed libglvnd libx11 libxcursor libxrandr libxinerama libxi libxxf86vm
```

### NixOS

Le plus propre sur NixOS est le **flake** de ce dépôt (l'exécutable est déjà
« wrappé » avec toutes les bibliothèques nécessaires) :

```bash
nix run github:CaporalDead/go_extract          # lance la GUI
nix profile install github:CaporalDead/go_extract   # ou l'installer dans le profil
```

Alternatives sans flake :

```bash
# L'AppImage via l'exécuteur d'AppImage de NixOS
nix-shell -p appimage-run --run 'appimage-run ./go_extract-linux-amd64.AppImage'
```

```nix
# ou exposer les libs pour le binaire nu (nix-ld), dans configuration.nix :
programs.nix-ld.enable = true;
programs.nix-ld.libraries = with pkgs; [
  libGL libxkbcommon
  xorg.libX11 xorg.libXcursor xorg.libXi xorg.libXrandr xorg.libXinerama xorg.libXxf86vm
];
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

## Binaires pré-construits (Releases)

À chaque tag `vX.Y.Z`, GitHub Actions construit et **publie une Release** :
**Releases** du dépôt → dernière version.

| Fichier | Plateforme |
|---|---|
| `go_extract-windows-amd64.exe` | Windows 64 bits |
| `go_extract-macos-arm64` | macOS Apple Silicon (M1/M2/M3…) |
| `go_extract-macos-amd64` | macOS Intel |
| `go_extract-linux-amd64.AppImage` | Linux (distributions standard) — fichier unique |
| `go_extract-linux-amd64` | Linux — binaire nu (libs OpenGL/X11 requises) |

> ⚠️ Les binaires ne sont **pas signés** (signature de code = certificats
> payants). Au premier lancement :
> - **Windows** : SmartScreen → « Informations complémentaires » → « Exécuter
>   quand même ».
> - **macOS** : clic droit → « Ouvrir » → « Ouvrir » (contourne Gatekeeper).
>   Si besoin : `xattr -dr com.apple.quarantine go_extract-macos-*`.
> - **Linux** : `chmod +x go_extract-linux-amd64` avant de lancer.

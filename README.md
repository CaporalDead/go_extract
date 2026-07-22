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

## Version ligne de commande `rxdecrypt` (sans dépendances)

`rxdecrypt` fait la même chose **sans interface graphique**. C'est un binaire
**100 % statique** : il ne dépend d'**aucune** bibliothèque système (ni OpenGL,
ni X11). À utiliser si la version graphique ne se lance pas (voir plus bas), ou
sur un serveur / une machine minimale / WSL.

```
rxdecrypt -src DOSSIER            -key VOTRE_CLE_HEX     -out DOSSIER_SORTIE
rxdecrypt -enc a.zip.enc -pub a.sign.pub -sig a.zip.enc.sig -key @cle.txt -out .
```

Il est publié dans les Releases : `rxdecrypt-<os>-<arch>` (Linux amd64/arm64,
Windows, macOS Intel/Apple Silicon).

## Prérequis d'exécution de la version graphique (Linux)

La version graphique utilise OpenGL : si vous obtenez
`error while loading shared libraries: libGL.so.1`, installez les bibliothèques
d'exécution (ou utilisez `rxdecrypt` ci-dessus) :

```
# Debian / Ubuntu
sudo apt-get install -y libgl1 libx11-6 libxcursor1 libxrandr2 libxinerama1 libxi6 libxxf86vm1
# Fedora
sudo dnf install -y mesa-libGL libX11 libXcursor libXrandr libXinerama libXi libXxf86vm
# Arch
sudo pacman -S --needed libglvnd libx11 libxcursor libxrandr libxinerama libxi libxxf86vm
```

Sur un poste de bureau Linux classique, ces bibliothèques sont déjà présentes.

### NixOS

Sur NixOS, on n'installe pas les libs globalement. La **CLI `rxdecrypt`** est un
binaire Go **statique** : elle fonctionne **directement**, sans rien installer.

Pour la **version graphique**, il faut exposer les dépendances OpenGL/X11.
Paquets nixpkgs requis :

```
libGL libxkbcommon
xorg.libX11 xorg.libXcursor xorg.libXi xorg.libXrandr xorg.libXinerama xorg.libXxf86vm
```

Trois méthodes :

```bash
# A. Le plus simple (FHS, zéro config)
nix-shell -p steam-run --run 'steam-run ./go_extract-linux-amd64'

# B. nix-shell ciblé
nix-shell -p libGL libxkbcommon xorg.libX11 xorg.libXcursor xorg.libXi \
             xorg.libXrandr xorg.libXinerama xorg.libXxf86vm --run '
  export LD_LIBRARY_PATH=$(echo "$buildInputs" | tr " " "\n" | sed "s|$|/lib|" | paste -sd:):/run/opengl-driver/lib
  ./go_extract-linux-amd64
'
```

```nix
# C. Permanent, dans configuration.nix (puis: nixos-rebuild switch)
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

À chaque tag `vX.Y.Z`, GitHub Actions construit et **publie une Release** avec
les 4 binaires : **Releases** du dépôt → dernière version.

| Fichier | Plateforme |
|---|---|
| `go_extract-windows-amd64.exe` | Windows 64 bits |
| `go_extract-macos-arm64` | macOS Apple Silicon (M1/M2/M3…) |
| `go_extract-macos-amd64` | macOS Intel |
| `go_extract-linux-amd64` | Linux 64 bits |

> ⚠️ Les binaires ne sont **pas signés** (signature de code = certificats
> payants). Au premier lancement :
> - **Windows** : SmartScreen → « Informations complémentaires » → « Exécuter
>   quand même ».
> - **macOS** : clic droit → « Ouvrir » → « Ouvrir » (contourne Gatekeeper).
>   Si besoin : `xattr -dr com.apple.quarantine go_extract-macos-*`.
> - **Linux** : `chmod +x go_extract-linux-amd64` avant de lancer.

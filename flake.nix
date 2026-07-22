{
  description = "go_extract — déchiffrement des archives de réversibilité Monkey Factory (GUI Fyne)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Ciblé Linux : c'est le cas d'usage NixOS (sous macOS/Windows, utilisez les
  # binaires publiés dans les Releases). Le paquet est un build Nix « propre » :
  # l'exécutable est lié (rpath) aux bibliothèques OpenGL/X11 du store, donc il se
  # lance directement sur NixOS sans erreur `libGL.so.1`.
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        guiLibs = with pkgs; [
          libGL
          libxkbcommon
          xorg.libX11
          xorg.libXcursor
          xorg.libXi
          xorg.libXrandr
          xorg.libXinerama
          xorg.libXxf86vm
        ];
        go_extract = pkgs.buildGoModule {
          pname = "go_extract";
          version = "2.0.0";
          src = self;

          # Rejouer si les dépendances changent : mettre lib.fakeHash puis
          # copier le hash indiqué par `nix build`.
          vendorHash = "sha256-2lLgIO613ltQyUvvUbUZJzMxj5ZmHZlAvPPreHyGFfQ=";

          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = guiLibs;

          # On ne construit que l'appli GUI (racine du module).
          subPackages = [ "." ];

          # Valide la crypto pendant le build (tests purs, sans GUI).
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            go test ./internal/rxcrypto/...
            runHook postCheck
          '';

          meta = with pkgs.lib; {
            description = "Déchiffrement des archives de réversibilité (vérif. Ed25519 + secretstream)";
            homepage = "https://github.com/CaporalDead/go_extract";
            platforms = platforms.linux;
            mainProgram = "go_extract";
          };
        };
      in {
        packages.default = go_extract;
        packages.go_extract = go_extract;

        apps.default = {
          type = "app";
          program = "${go_extract}/bin/go_extract";
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.go pkgs.pkg-config ];
          buildInputs = guiLibs;
          # Pour lancer un build local depuis le devShell.
          shellHook = ''
            echo "devShell go_extract — go build -o go_extract ."
          '';
        };
      });
}

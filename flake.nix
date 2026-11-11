{
  description = "bxplore: viewer and editor for PE, ELF and Mach-O files";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # Linux only. macOS and Windows have their own packages (see packaging/).
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      manifest = (nixpkgs.lib.importTOML ./Cargo.toml).package;
      appId = "io.github.bxplore.Bxplore";
      # The GUI opens these at run time; nothing links against them.
      runtimeLibsFor =
        pkgs: with pkgs; [
          libGL
          libxkbcommon
          wayland
          libx11
          libxcursor
          libxi
          libxrandr
          libxcb
        ];
    in
    {
      packages = forAll (
        pkgs:
        let
          runtimeLibs = runtimeLibsFor pkgs;
        in
        rec {
          bxplore = pkgs.rustPlatform.buildRustPackage {
            pname = manifest.name;
            version = manifest.version;
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter =
                path: type:
                let
                  rel = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
                in
                !(
                  pkgs.lib.hasPrefix "target" rel || pkgs.lib.hasPrefix "dist" rel || pkgs.lib.hasPrefix "fuzz" rel
                );
            };
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [ pkgs.makeWrapper ];
            # The tests build fixtures with compilers that are not in the sandbox.
            doCheck = false;

            postInstall = ''
              install -Dm644 packaging/linux/bxplore.desktop $out/share/applications/${appId}.desktop
              install -Dm644 packaging/icons/bxplore-256.png $out/share/icons/hicolor/256x256/apps/${appId}.png
              install -Dm644 packaging/icons/bxplore-512.png $out/share/icons/hicolor/512x512/apps/${appId}.png
              install -Dm644 packaging/icons/bxplore.svg $out/share/icons/hicolor/scalable/apps/${appId}.svg
            '';
            postFixup = ''
              wrapProgram $out/bin/bxplore --prefix LD_LIBRARY_PATH : ${pkgs.lib.makeLibraryPath runtimeLibs}
            '';

            meta = {
              description = manifest.description or "Viewer and editor for PE, ELF and Mach-O files";
              license = pkgs.lib.licenses.mit;
              mainProgram = "bxplore";
              platforms = systems;
            };
          };
          default = bxplore;
        }
      );

      apps = forAll (pkgs: rec {
        bxplore = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.bxplore}/bin/bxplore";
        };
        default = bxplore;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.bxplore ];
          packages = with pkgs; [
            clippy
            rustfmt
            rust-analyzer
          ];
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (runtimeLibsFor pkgs);
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-rfc-style);
    };
}

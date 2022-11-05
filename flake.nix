{
  description = "Keepass Library for Rust";

  outputs = { self, nixpkgs }: 
  let 
    systems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
    makeSystemMap = f: system: { name = system; value = f system; };
    forAllSystems = f: builtins.listToAttrs (builtins.map (makeSystemMap f) systems);
  in
  {
    packages = forAllSystems (system:
      let pkgs = nixpkgs.legacyPackages.${system}; 
      in {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "kdbx-rs";
          version = "0.2.2";
          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };
      }
    );
  };
}

{
  description = "Sandboxed AI coding environment via podman";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      packages = builtins.listToAttrs (
        map
          (system: {
            name = system;
            value = {
              # callPackage (not a plain import) so downstream users can
              # customise with `.override { defaultAgent = …; }`.
              default = nixpkgs.legacyPackages.${system}.callPackage ./default.nix { };
            };
          })
          systems
      );

      apps = builtins.listToAttrs (
        map
          (system: {
            name = system;
            value.default = {
              type = "app";
              program = "${self.packages.${system}.default}/bin/agent-sandbox";
            };
          })
          systems
      );

      overlays.default = _final: _prev: { };
    };
}

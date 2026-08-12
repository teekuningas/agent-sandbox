{
  description = "Sandboxed AI coding environment via podman";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.antigravity-nix = {
    url = "github:jacopone/antigravity-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      antigravity-nix,
      ...
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              # claude-code and google-antigravity-cli are unfree.
              config.allowUnfree = true;
              overlays = [ antigravity-nix.overlays.default ];
            }
          )
        );

      packageFor = system: self.packages.${system}.default;


    in
    {
      packages = forAllSystems (pkgs: rec {
        default = lib.makeOverridable (import ./default.nix) { inherit pkgs lib; };
        # The image itself, for `nix build .#image` and for shipping it
        # somewhere other than the local podman store.
        image = default.passthru.image;
      });

      apps = lib.genAttrs systems (
        system:
        let
          package = packageFor system;
        in
        {
          default = { type = "app"; program = "${package}/bin/agent-sandbox"; meta = { description = "Sandboxed AI coding environment via podman"; }; };
          ctl = { type = "app"; program = "${package}/bin/agent-sandbox-ctl"; meta = { description = "agent-sandbox utility for managing running sandboxes"; }; };
        }
      );

      # `nix flake check` runs the parser and gnupg-classifier test suites and
      # shellchecks every script, without building the container image.
      checks = lib.genAttrs systems (system: (packageFor system).passthru.checks);

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}

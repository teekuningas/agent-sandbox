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
        # The cooperative host browser, with a pinned Chromium.  Kept out of
        # `default` so a plain install does not carry a browser closure;
        # `agent-sandbox browser` from that install uses a Chromium on PATH.
        browser = default.passthru.browserLauncher;
      });

      apps = lib.genAttrs systems (
        system:
        let
          package = packageFor system;
        in
        {
          default = { type = "app"; program = "${package}/bin/agent-sandbox"; meta = { description = "Sandboxed AI coding environment via podman"; }; };
          browser = { type = "app"; program = "${package.passthru.browserLauncher}/bin/agent-sandbox-browser"; meta = { description = "Throwaway host browser behind a deny-by-default allow list"; }; };
        }
      );

      # `nix flake check` builds the Rust workspace, which runs `cargo test`
      # over the launcher, parser and policy suites, without building the
      # container image.
      checks = lib.genAttrs systems (system: (packageFor system).passthru.checks);

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}

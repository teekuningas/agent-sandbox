{
  pkgs,
  lib,
  agents ? import ./agents.nix { inherit pkgs; },
  defaultAgent ? "opencode",
  # Unpacked Chromium extensions `agent-sandbox browser` loads by default, as
  # store paths.  Empty on purpose: nixpkgs packages no Chrome extensions, so a
  # default would mean pinning a release artifact from somewhere else, and the
  # ephemeral profile is better off minimal.  Override to add your own:
  #
  #   (import ./default.nix { inherit pkgs lib; }).override {
  #     browserExtensions = [ ./my-extension ];
  #   }
  browserExtensions ? [ ],
}:

let
  imageName = "agent-sandbox";
  imageTag = "latest";
  # podman namespaces locally loaded images under localhost/.
  imageRef = "localhost/${imageName}:${imageTag}";

  # Shared network for --shared-network, where sibling containers reach a
  # sandbox by name.  Only created when that flag asks for it: publishing a port
  # does not need it, and a bridge would cost the pasta options that are the
  # only route to the host's loopback.
  networkName = "agent-sandbox";

  # Scripts in ./lib keep their own shebang so they can be run and linted in
  # place; the Nix writers supply theirs, so drop the first line.
  scriptBody =
    path: lib.concatStringsSep "\n" (lib.drop 1 (lib.splitString "\n" (builtins.readFile path)));

  # Full rootless podman stack (c.f. devenv-module-devcontainer/tweaks/podman.nix):
  # the extra binaries let nested podman build/run work inside the container when
  # it is launched with enough privileges; the host socket forward gives a
  # reliable "sibling container" mode that needs no privileges.
  podmanStack = with pkgs; [
    podman
    crun
    conmon
    skopeo
    slirp4netns
    fuse-overlayfs
  ];

  # `docker` alias so anything calling docker hits podman.
  dockerAlias = pkgs.writeShellScriptBin "docker" ''exec ${pkgs.podman}/bin/podman "$@"'';

  # Build the entire Cargo workspace containing proxy and cli binaries
  agentSandboxRust = pkgs.rustPlatform.buildRustPackage {
    pname = "agent-sandbox-rust";
    version = "0.1.0";
    src = lib.cleanSource ./.;
    cargoLock = {
      lockFile = ./Cargo.lock;
    };
  };

  sidecarScript = pkgs.writeShellScriptBin "agent-sandbox-sidecar" ''
    exec ${agentSandboxRust}/bin/agent-sandbox-sidecar "$@"
  '';
  proxyScript = pkgs.writeShellScriptBin "agent-sandbox-proxy" ''
    exec ${agentSandboxRust}/bin/agent-sandbox-proxy "$@"
  '';

  # Wraps the two-step `nix build` + `nix shell` dance from the browser skill
  # into one command, so PLAYWRIGHT_BROWSERS_PATH can never fail to survive
  # into the command that needs it. A script, not a baked-in closure: the
  # browser binaries are heavy and most sessions never touch one, so this
  # stays an on-demand nixpkgs fetch like every other tool in the `nix` skill
  # rather than growing the image. FONTCONFIG_FILE is already exported
  # image-wide, so this only needs to shell in python3 + the playwright package.
  playwrightPython = pkgs.writeShellApplication {
    name = "playwright-python";
    runtimeInputs = [ pkgs.nix ];
    text = ''
      # The single-quoted --expr strings below are Nix syntax for the nested
      # `nix build`/`nix shell` to evaluate, not shell variables to expand
      # here -- shellcheck's suggestion to double-quote them would be wrong.
      # shellcheck disable=SC2016
      PLAYWRIGHT_BROWSERS_PATH=$(nix build --impure --expr \
        'with (builtins.getFlake "nixpkgs").legacyPackages.''${builtins.currentSystem}; playwright-driver.browsers' \
        --no-link --print-out-paths)
      export PLAYWRIGHT_BROWSERS_PATH
      # shellcheck disable=SC2016
      exec nix shell --impure --expr \
        'with (builtins.getFlake "nixpkgs").legacyPackages.''${builtins.currentSystem}; python3.withPackages (ps: [ ps.playwright ])' \
        --command python3 "$@"
    '';
  };

  # The SSH/GPG relay, in both halves: relay-server runs in the sidecar next to
  # the forwarded host sockets, relay-ssh/relay-gpg run in the sandbox, which
  # has no socket of its own under --proxy.  Individually wrapped rather than
  # putting the whole Rust closure on the image PATH, which would also hand the
  # agent the launcher and the ctl commands.
  relayScripts = map (
    name: pkgs.writeShellScriptBin name ''exec ${agentSandboxRust}/bin/${name} "$@"''
  ) [ "relay-server" "relay-ssh" "relay-gpg" ];

  # Headless Chromium renders nothing legible without fonts, and it fails
  # *silently*: the page loads, the DOM is correct, and every screenshot comes
  # back one flat colour.  Shipping a minimal set turns that trap into a
  # non-event for anything launched from the image.
  imageFonts = with pkgs; [ dejavu_fonts liberation_ttf ];
  # `makeFontsConf` writes a bare file, and the image root is assembled with
  # `pkgs.buildEnv`, which can only merge directories -- a file among its paths
  # fails the build.  So the config is wrapped in a directory, and not at
  # /etc/fonts/fonts.conf: fontconfig ships its own copy of that path and the
  # two would collide.
  imageFontsConf = pkgs.runCommand "agent-sandbox-fonts-conf" { } ''
    install -Dm444 ${pkgs.makeFontsConf { fontDirectories = imageFonts; }} \
      "$out/share/agent-sandbox/fonts.conf"
  '';
  imageFontsConfFile = "${imageFontsConf}/share/agent-sandbox/fonts.conf";
  unknownAgent = throw "agent-sandbox: unknown default agent '${defaultAgent}'";
  defaultAgentDef = lib.findFirst (a: a.name == defaultAgent) unknownAgent agents;
  agentTools = map (a: a.package) agents;
  agentSpecs = lib.concatStringsSep "\n" (
    map (
      a:
      lib.concatStringsSep "\t" [
        a.name
        (builtins.toJSON a.command)
        (builtins.toJSON (a.state or [ ]))
        (builtins.toJSON (a.stateFiles or [ ]))
      ]
    ) agents
  );

  baseTools =
    with pkgs;
    [
      openssh
      bashInteractive
      coreutils
      findutils
      gnugrep
      gnupg
      gnused
      gawk
      which
      curl
      wget
      ripgrep
      procps
      fd
      jq
      diffutils
      patch
      file
      tree
      gnutar
      gzip
      unzip
      xz
      bzip2
      zstd
      python3
      uv
      gnumake
      vim
      less
      man-db
      man-pages
      tmux
      htop
      lsof
      strace
      rsync
      perl
      sudo
      shadow
      util-linux
      iproute2
      nettools
      dnsutils
      openssl
      # socat backs the entrypoint's generated ssh ProxyCommand under --proxy.
      socat
      git-lfs
      nix
      devenv
      inotify-tools
      git
      gh
      nodejs
      stdenv.cc.cc.lib
      zlib
      glibcLocales
      fontconfig
    ]
    ++ imageFonts
    ++ podmanStack
    # No agent-sandbox-allow: policy now lives on a volume the sandbox cannot
    # see, so widening the firewall is a host-side operation
    # (agent-sandbox ctl proxy allow) by design.
    ++ [ dockerAlias sidecarScript proxyScript playwrightPython ]
    ++ relayScripts;

  tools = baseTools ++ agentTools;

  nixConf = pkgs.writeTextFile {
    name = "nix-conf";
    destination = "/etc/nix/nix.conf";
    text = ''
      sandbox = false
      filter-syscalls = false
      experimental-features = nix-command flakes
      build-users-group =
    '';
  };

  # The system-level include of the entrypoint's generated gitconfig, so it also
  # reaches a git that was started without the GIT_CONFIG_* environment the
  # entrypoint sets -- a `podman exec` shell, or a git spawned by a tool that
  # scrubs its child environment.  Git ignores an include whose path does not
  # exist, so this is inert in a container that never wrote one.
  etcGitconfig = pkgs.writeTextFile {
    name = "etc-gitconfig";
    destination = "/etc/gitconfig";
    text = ''
      [include]
      	path = /home/user/.config/agent-sandbox/gitconfig
    '';
  };

  # Rootless podman container config baked into the image so nested podman is
  # pre-configured. helper_binaries_dir points at the nix store paths so podman
  # inside the image can find crun/fuse-overlayfs without a PATH search.
  containersConf = pkgs.writeTextFile {
    name = "containers-conf";
    destination = "/etc/containers/containers.conf";
    text = ''
      [engine]
      helper_binaries_dir = ["${pkgs.podman}/libexec/podman", "${pkgs.crun}/bin", "${pkgs.fuse-overlayfs}/bin"]
      runtime = "crun"
      [containers]
      pids_limit = 0
    '';
  };

  storageConf = pkgs.writeTextFile {
    name = "storage-conf";
    destination = "/etc/containers/storage.conf";
    text = ''
      [storage]
      driver = "overlay"
    '';
  };

  registriesConf = pkgs.writeTextFile {
    name = "registries-conf";
    destination = "/etc/containers/registries.conf";
    text = ''
      [registries]
      [registries.block]
      registries = []
      [registries.insecure]
      registries = []
      [registries.search]
      registries = ["docker.io", "quay.io"]
    '';
  };

  policyConf = pkgs.writeTextFile {
    name = "policy-conf";
    destination = "/etc/containers/policy.json";
    text = ''
      {"default":[{"type":"insecureAcceptAnything"}],"transports":{"default-daemon":{"":[{"type":"insecureAcceptAnything"}]}}}
    '';
  };

  # All paths baked into the image root, shared between the root env and
  # closureInfo so they stay in sync.
  containerPaths = tools ++ [
    pkgs.cacert
    # Referenced only from the image's FONTCONFIG_FILE, so it has to be named
    # here or it would not be in the closure the image ships.
    imageFontsConf
    nixConf
    etcGitconfig
    containersConf
    storageConf
    registriesConf
    policyConf
  ];

  # Loaded into the nix DB on first container start so nix treats baked-in
  # store paths as valid and won't attempt to re-substitute them.
  storeRegistration = pkgs.closureInfo { rootPaths = containerPaths; };

  rootEnv = pkgs.buildEnv {
    name = "agent-sandbox-root";
    paths = containerPaths;
  };

  # Prebuilt native binaries shipped by npm packages (lightningcss, esbuild,
  # @swc/core, …) hard-code the ELF interpreter path, which is architecture
  # specific.  An unknown system is a build error rather than a dangling
  # symlink that only fails once someone runs the affected tool.
  elfInterpreter =
    {
      "x86_64-linux" = {
        dir = "lib64";
        name = "ld-linux-x86-64.so.2";
      };
      "aarch64-linux" = {
        dir = "lib";
        name = "ld-linux-aarch64.so.1";
      };
    }
    .${pkgs.stdenv.hostPlatform.system}
      or (throw "agent-sandbox: no ELF interpreter mapping for ${pkgs.stdenv.hostPlatform.system}");

  entrypoint = pkgs.writeShellScript "agent-sandbox-entrypoint" ''
    exec ${agentSandboxRust}/bin/agent-sandbox-entrypoint "$@"
  '';

  # streamLayeredImage with maxLayers = 2 (minimum allowed): produces a minimal-layer image stream
  # to minimize podman load extraction overhead, overlayfs mount parameter
  # sizes, and VFS dentry lookup latency during container startup, while still
  # streaming the tar output to stdout without materializing a multi-gigabyte
  # tarball in the host Nix store.
  image = pkgs.dockerTools.streamLayeredImage {
    name = imageName;
    tag = imageTag;
    maxLayers = 2;

    contents = [ rootEnv ];

    extraCommands = ''
      mkdir -p usr/bin
      ln -s ${pkgs.coreutils}/bin/env usr/bin/env

      test -e ${pkgs.glibc}/lib/${elfInterpreter.name}
      mkdir -p ${elfInterpreter.dir}
      ln -sf ${pkgs.glibc}/lib/${elfInterpreter.name} ${elfInterpreter.dir}/${elfInterpreter.name}

      mkdir -p home/user
      chmod 1777 home/user
      # The whole skill tree ships as-is: each skill is a SKILL.md plus any
      # reference files it links to for progressive disclosure.
      mkdir -p home/user/.agents/skills
      cp -R ${./skills}/. home/user/.agents/skills/
      chmod -R u+w home/user/.agents/skills
      # Several agent tools discover skills from their own home directory.
      # Keep one canonical tree and expose it through compatibility symlinks.
      for tool in claude codex copilot cursor gemini; do
        mkdir -p "home/user/.$tool"
        ln -s /home/user/.agents/skills "home/user/.$tool/skills"
      done
      mkdir -p workspace
      chmod 1777 workspace
      mkdir -p tmp
      chmod 1777 tmp
      mkdir -p var
      chmod u+w var
      mkdir -p var/tmp
      chmod 1777 var/tmp

      mkdir -p nix/store
      chmod 1777 nix/store

      mkdir -p nix/var/nix/db
      mkdir -p nix/var/nix/profiles
      mkdir -p nix/var/nix/gcroots/profiles
      mkdir -p nix/var/nix/temproots
      mkdir -p nix/var/nix/userpool
      mkdir -p nix/var/log/nix/drvs
      chmod -R 1777 nix/var

      cp ${storeRegistration}/registration nix/registration
    '';

    config = {
      WorkingDir = "/workspace";
      Entrypoint = [ "${entrypoint}" ];
      Cmd = defaultAgentDef.command;
      Env = [
        "PATH=${lib.makeBinPath tools}"
        "LD_LIBRARY_PATH=${
          lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib
            pkgs.zlib
          ]
        }"
        "HOME=/home/user"
        "USER=user"
        "TERM=xterm-256color"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "LANG=en_US.UTF-8"
        "LOCALE_ARCHIVE=${pkgs.glibcLocales}/lib/locale/locale-archive"
        # See `imageFonts`: without this a headless screenshot is a flat colour
        # and nothing says so.
        "FONTCONFIG_FILE=${imageFontsConfFile}"
        # Force Go programs to use the C library (glibc) DNS resolver.
        # Go's pure-Go resolver sends raw UDP queries that time out on
        # slirp4netns's DNS forwarder in rootless Podman, causing 5s delays.
        "GODEBUG=netdns=cgo"
      ];
    };
  };

  # Under --nix the launcher mounts host /nix over the image store, so image
  # referenced paths must stay rooted in this package closure as well.
  imageStorePaths = pkgs.writeTextDir "share/agent-sandbox/image-store-paths" (
    lib.concatMapStringsSep "\n" toString (
      lib.concatMap (p: map (o: p.${o}) (p.outputs or [ "out" ])) containerPaths ++ [ entrypoint ]
    )
  );



  # Every launcher-adjacent script gets its image/network identifiers from
  # here rather than hard-coding them, and writeShellApplication runs
  # shellcheck over the result at build time.
  preamble = ''
    export AGENT_SANDBOX_IMAGE="${imageRef}"
    export AGENT_SANDBOX_NETWORK="${networkName}"
  '';

  # An absolute store path rather than a bare "krun", because podman resolves a
  # bare --runtime name against containers.conf and would find whatever the host
  # happens to have configured.  Note this is unrelated to the runtime = "crun"
  # in the image's own containers.conf below, which configures *nested* podman.
  #
  # nixpkgs builds crun with --with-libkrun by default and substitutes the
  # absolute libkrun.so.1 path into the binary, so no LD_LIBRARY_PATH is needed;
  # libkrun's own RPATH then covers libkrunfw.so.  If a nixpkgs change ever flips
  # withLibkrun off, the launcher's preflight catches it at first use -- probing
  # for it here would mean running crun during evaluation.
  launcherPreamble = preamble + ''
    export AGENT_SANDBOX_AGENT_SPECS=${lib.escapeShellArg agentSpecs}
    export AGENT_SANDBOX_KRUN_RUNTIME="${pkgs.crun}/bin/krun"
    export AGENT_SANDBOX_IMAGE_STREAM="${image}"
  '';

  launcher = pkgs.writeShellApplication {
    name = "agent-sandbox";
    runtimeInputs = with pkgs; [
      agentSandboxRust podman git coreutils jq gnupg util-linux findutils gnugrep gawk secretspec
    ];
    text = launcherPreamble + ''
      exec ${agentSandboxRust}/bin/agent-sandbox "$@"
    '';
  };

  ctlLauncher = pkgs.writeShellApplication {
    name = "agent-sandbox-ctl";
    runtimeInputs = with pkgs; [
      agentSandboxRust podman git coreutils jq gnupg util-linux findutils gnugrep gawk secretspec
    ];
    text = launcherPreamble + ''
      exec ${agentSandboxRust}/bin/agent-sandbox ctl "$@"
    '';
  };

  # `agent-sandbox browser` with a browser of its own.
  #
  # Deliberately *not* part of the default package: Chromium is a large closure
  # and most sandboxes never start a browser.  `agent-sandbox browser` still
  # works from the plain install against a Chromium already on PATH; this is
  # what makes `nix run .#browser` work on a host with no browser at all, and
  # what pins the version the managed-policy layer was written against.
  #
  # chromium rather than google-chrome, and not only as a licence preference:
  # branded Chrome dropped --load-extension in 137 and
  # --disable-extensions-except in 139, which are how extensions reach an
  # ephemeral profile at all.  bubblewrap is what puts this instance's managed
  # policy where Chromium looks for it; the command degrades with a warning
  # when it is unusable, so it is an input rather than a requirement.
  browserLauncher = pkgs.writeShellApplication {
    name = "agent-sandbox-browser";
    runtimeInputs = with pkgs; [
      agentSandboxRust podman coreutils chromium bubblewrap
    ];
    text = launcherPreamble + ''
      export AGENT_SANDBOX_BROWSER_CHROMIUM="${pkgs.chromium}/bin/chromium"
      export AGENT_SANDBOX_BROWSER_EXTENSIONS=${
        lib.escapeShellArg (lib.concatMapStringsSep ":" toString browserExtensions)
      }
      exec ${agentSandboxRust}/bin/agent-sandbox ctl browser "$@"
    '';
  };

  # `rust` is the whole workspace: buildRustPackage runs `cargo test` in its
  # check phase, so this is what makes `nix flake check` cover the launcher's
  # argument handling, the AGENTS.md parsers and the policy format.
  checks = {
    rust = agentSandboxRust;
    proxy = proxyScript;
  };

in
pkgs.symlinkJoin {
  name = "agent-sandbox";
  paths = [
    launcher
    ctlLauncher
    imageStorePaths
  ];
  passthru = {
    inherit
      agents
      defaultAgent
      image
      checks
      launcher
      browserLauncher
      ;
  };
  meta = {
    description = "Sandboxed AI coding environment via podman";
    mainProgram = "agent-sandbox";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}

{
  pkgs,
  lib,
  agents ? import ./agents.nix { inherit pkgs; },
  defaultAgent ? "opencode",
}:

let
  imageName = "agent-sandbox";
  imageTag = "latest";
  # podman namespaces locally loaded images under localhost/.
  imageRef = "localhost/${imageName}:${imageTag}";

  # Shared network for port forwarding.  Only created when a sandbox actually
  # publishes something; see lib/agent-sandbox-port.sh for why it exists.
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

  sidecarScript = pkgs.writeShellScriptBin "agent-sandbox-sidecar" (scriptBody ./lib/agent-sandbox-sidecar.sh);
  allowScript = pkgs.writeShellScriptBin "agent-sandbox-allow" (scriptBody ./lib/agent-sandbox-allow.sh);
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
      # socat backs the port-forward sidecars; the image doubles as their image.
      socat
      git-lfs
      nix
      devenv
      tinyproxy
      inotify-tools
      tcpdump
      wireshark-cli
      git
      gh
      nodejs
      stdenv.cc.cc.lib
      zlib
      glibcLocales
    ]
    ++ podmanStack
    ++ [ dockerAlias sidecarScript allowScript ];

  tools = baseTools ++ agentTools;

  nixConf = pkgs.writeTextFile {
    name = "nix-conf";
    destination = "/etc/nix/nix.conf";
    text = ''
      sandbox = false
      filter-syscalls = false
      experimental-features = nix-command flakes
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
    nixConf
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

  entrypoint = pkgs.writeShellScript "agent-sandbox-entrypoint" (scriptBody ./lib/entrypoint.sh);

  # streamLayeredImage rather than buildImage: layers are shared between
  # rebuilds and nothing materialises a multi-gigabyte tarball in the store.
  # The result is an executable that writes the tar to stdout.
  image = pkgs.dockerTools.streamLayeredImage {
    name = imageName;
    tag = imageTag;

    contents = [ rootEnv ];

    extraCommands = ''
      mkdir -p usr/bin
      ln -s ${pkgs.coreutils}/bin/env usr/bin/env

      test -e ${pkgs.glibc}/lib/${elfInterpreter.name}
      mkdir -p ${elfInterpreter.dir}
      ln -sf ${pkgs.glibc}/lib/${elfInterpreter.name} ${elfInterpreter.dir}/${elfInterpreter.name}

      mkdir -p home/user
      chmod 1777 home/user
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
        # Force Go programs to use the C library (glibc) DNS resolver.
        # Go's pure-Go resolver sends raw UDP queries that time out on
        # slirp4netns's DNS forwarder in rootless Podman, causing 5s delays.
        "GODEBUG=netdns=cgo"
      ];
    };
  };

  # The launcher mounts host /nix over the image store by default, so image
  # referenced paths must stay rooted in this package closure as well.
  imageStorePaths = pkgs.writeTextDir "share/agent-sandbox/image-store-paths" (
    lib.concatMapStringsSep "\n" toString (
      lib.concatMap (p: map (o: p.${o}) (p.outputs or [ "out" ])) containerPaths ++ [ entrypoint ]
    )
  );

  # ── Host-side helpers ─────────────────────────────────────────────────────

  # Kept out of the launcher so it can be unit-tested against fixture
  # keyrings, and because "is this GnuPG home card-only?" is a useful question
  # to be able to ask directly.
  gnupgScan = pkgs.writeShellApplication {
    name = "agent-sandbox-gnupg-scan";
    runtimeInputs = with pkgs; [
      coreutils
      findutils
    ];
    text = scriptBody ./lib/gnupg-scan.sh;
  };

  # Wrapper rather than an inlined script: the Python stays a real file that
  # `python3 -m unittest` can import directly.
  parseAgents = pkgs.writeShellApplication {
    name = "agent-sandbox-parse-agents";
    runtimeInputs = [ pkgs.python3 ];
    text = ''exec python3 ${./lib/parse_agents.py} "$@"'';
  };

  # Every launcher-adjacent script gets its image/network identifiers from
  # here rather than hard-coding them, and writeShellApplication runs
  # shellcheck over the result at build time.
  preamble = ''
    AGENT_SANDBOX_IMAGE="${imageRef}"
    AGENT_SANDBOX_NETWORK="${networkName}"
  '';

  launcherPreamble = preamble + ''
    AGENT_SANDBOX_AGENT_SPECS=${lib.escapeShellArg agentSpecs}
  '';

  launcher = pkgs.writeShellApplication {
    name = "agent-sandbox";
    runtimeInputs = with pkgs; [
      podman
      git
      coreutils
      jq
      gnupg       # gpgconf --list-dir agent-socket
      wireshark-cli # tshark for --meter-network cleanup
    ]
    ++ [
      gnupgScan
      parseAgents
    ];
    text = launcherPreamble + scriptBody ./lib/agent-sandbox.sh;
  };

  portScript = pkgs.writeShellApplication {
    name = "agent-sandbox-port";
    runtimeInputs = with pkgs; [
      podman
      coreutils
      gnugrep
    ];
    text = preamble + scriptBody ./lib/agent-sandbox-port.sh;
  };

  purgeScript = pkgs.writeShellApplication {
    name = "agent-sandbox-purge";
    runtimeInputs = with pkgs; [
      podman
      coreutils
      findutils
    ];
    text = preamble + scriptBody ./lib/agent-sandbox-purge.sh;
  };

  listScript = pkgs.writeShellApplication {
    name = "agent-sandbox-list";
    runtimeInputs = with pkgs; [ podman ];
    text = preamble + scriptBody ./lib/agent-sandbox-list.sh;
  };

  loadScript = pkgs.writeShellApplication {
    name = "agent-sandbox-load";
    runtimeInputs = [ pkgs.podman ];
    text = ''
      AGENT_SANDBOX_IMAGE="${imageRef}"
      AGENT_SANDBOX_IMAGE_STREAM="${image}"
    ''
    + scriptBody ./lib/agent-sandbox-load.sh;
  };

  ctlScript = pkgs.writeShellApplication {
    name = "agent-sandbox-ctl";
    runtimeInputs = [
      loadScript
      portScript
      purgeScript
      listScript
    ];
    text = scriptBody ./lib/agent-sandbox-ctl.sh;
  };

  # ── Checks ────────────────────────────────────────────────────────────────
  # Building the launcher already runs shellcheck (writeShellApplication), so
  # these cover what that cannot: the parser's behaviour, the gnupg
  # classifier's verdicts, and the entrypoint, which is a plain script.

  checks = {
    parser = pkgs.runCommand "agent-sandbox-parser-tests" { nativeBuildInputs = [ pkgs.python3 ]; } ''
      cp ${./lib/parse_agents.py} parse_agents.py
      cp ${./lib/test_parse_agents.py} test_parse_agents.py
      python3 -m unittest test_parse_agents -v
      touch "$out"
    '';

    gnupg-scan =
      pkgs.runCommand "agent-sandbox-gnupg-tests"
        {
          nativeBuildInputs = with pkgs; [
            bash
            coreutils
            gnugrep
          ];
        }
        ''
          bash ${./lib/test-gnupg-scan.sh} ${gnupgScan}/bin/agent-sandbox-gnupg-scan
          touch "$out"
        '';

    launcher-args =
      pkgs.runCommand "agent-sandbox-launcher-arg-tests"
        {
          nativeBuildInputs = with pkgs; [
            bash
            coreutils
            gnugrep
            jq
          ];
        }
        ''
          bash ${./lib/test-launcher-args.sh} ${./lib/agent-sandbox.sh}
          touch "$out"
        '';

    shellcheck = pkgs.runCommand "agent-sandbox-shellcheck" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
      shellcheck --shell=bash ${./lib}/*.sh
      touch "$out"
    '';

    # Builds every host-side script, which is what runs shellcheck over the
    # generated (preamble + body) text.  Deliberately excludes the load
    # script, so `nix flake check` does not have to build the image.
    scripts = pkgs.symlinkJoin {
      name = "agent-sandbox-scripts";
      paths = [
        launcher
        portScript
        purgeScript
        listScript
        ctlScript
        gnupgScan
        parseAgents
      ];
    };
  };

in
pkgs.symlinkJoin {
  name = "agent-sandbox";
  paths = [
    launcher
    ctlScript
    imageStorePaths
  ];
  passthru = {
    inherit
      agents
      defaultAgent
      image
      checks
      launcher
      loadScript
      portScript
      purgeScript
      listScript
      ctlScript
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

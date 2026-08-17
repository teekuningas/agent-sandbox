# An agent is a CLI command plus the home paths that persist its login state.
{ pkgs }:
[
  {
    name = "opencode";
    package = pkgs.opencode;
    command = [
      "opencode"
      "."
    ];
    state = [
      ".local/share/opencode"
      ".config/opencode"
      ".cache/opencode"
    ];
  }
  {
    name = "claude";
    package = pkgs.claude-code;
    command = [ "claude" ];
    state = [ ".claude" ];
    stateFiles = [ ".claude.json" ];
  }
  {
    name = "copilot";
    package = pkgs.github-copilot-cli;
    command = [ "copilot" ];
    state = [ ".copilot" ];
  }
  {
    name = "antigravity";
    package = pkgs.google-antigravity-cli;
    command = [
      "agy"
      "."
    ];
    state = [
      ".local/share/antigravity-cli"
      ".config/antigravity-cli"
      ".cache/antigravity-cli"
      ".gemini"
    ];
  }
  {
    name = "codex";
    package = pkgs.codex;
    command = [
      "codex"
      "."
    ];
    state = [
      ".codex"
    ];
  }
]

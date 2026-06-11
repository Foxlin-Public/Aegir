# Installer Guide

The wrapped installers bootstrap only the Beta-1 SDK packages and local MCP wrapper in this repository.

They do not install hosted deployment services, systemd units, reverse-proxy configuration, production runtime code, or Foxlin infrastructure automation.

## PowerShell

```powershell
pwsh ./installers/install-sdk.ps1 -DotNet -Node -Java -Python -Go -Mcp
```

Supported switches:

- `-DotNet`
- `-Node`
- `-Java`
- `-Python`
- `-Go`
- `-Mcp`
- `-All`

## Shell

```bash
bash ./installers/install-sdk.sh --dotnet --node --java --python --go --mcp
```

Supported flags:

- `--dotnet`
- `--node`
- `--java`
- `--python`
- `--go`
- `--mcp`
- `--all`

## Behavior

The installers:

- print the Beta-1 SDK version
- install package-level dependencies where required
- build the local Node package when requested
- prepare the local MCP package for stdio use
- do not publish anything

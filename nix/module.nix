# NixOS module: the Dentrado identity service (auth, v7).
#
# Pure wiring: options -> one system user + one sandboxed systemd
# unit. The module never touches secret material: the signer bundle,
# the pepper and the TLS key are provisioned by the administrator out
# of band and only referenced by path. The binary itself enforces the
# secret-file contract (mode 0400/0600, pepper outside the state dir)
# — a violation fails the service start, not the eval.
#
# Minimal configuration:
#
#   services.dentrado-auth = {
#     enable = true;
#     bundle = "/etc/dentrado-auth/signer.bin";
#     pepper = "/etc/dentrado-auth/pepper.bin";
#     tlsCert = "/etc/dentrado-auth/fullchain.pem";
#     tlsKey  = "/etc/dentrado-auth/privkey.pem";
#   };
#
# Secret files must be owned by the service user (`dentrado-auth`)
# with mode 0400/0600; the state lives in /var/lib/dentrado-auth.
# Key generation runbook: README §7 ("Quick start").
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.dentrado-auth;

  stateDir = "/var/lib/dentrado-auth";

  # The TCP port of a "host:port" / "[v6]:port" listen address.
  listenPort = strings.toInt (last (splitString ":" cfg.listen));
in
{
  options.services.dentrado-auth = {
    enable = mkEnableOption "the Dentrado identity service (IS)";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "The package providing the auth binary.";
    };

    bundle = mkOption {
      type = types.str;
      example = "/etc/dentrado-auth/signer.bin";
      description = ''
        The signer bundle (`auth signer new` output) — the server's
        PERMANENT secret, fed at every start. Mode 0400/0600, owned by
        the dentrado-auth user.
      '';
    };

    pepper = mkOption {
      type = types.str;
      example = "/etc/dentrado-auth/pepper.bin";
      description = ''
        The 32-byte pepper file, on storage separate from the state
        dir (never under ${stateDir}). Mode 0400/0600, owned by the
        dentrado-auth user.
      '';
    };

    listen = mkOption {
      type = types.str;
      default = "0.0.0.0:7001";
      description = ''
        Listen address. TLS terminates in-process (rustls); there is
        no reverse proxy in front of the IS by design.
      '';
    };

    tlsCert = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/etc/dentrado-auth/fullchain.pem";
      description = ''
        PEM certificate chain; together with tlsKey it enables
        in-process HTTPS. Null — plain HTTP (dev/localhost only).
      '';
    };

    tlsKey = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/etc/dentrado-auth/privkey.pem";
      description = ''
        PEM private key (a server secret: mode 0400/0600, owned by
        the dentrado-auth user).
      '';
    };

    host = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "WebAuthn rpId override; default: the host of the bundle origin.";
    };

    webOrigin = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "WebAuthn origin override; default: the bundle origin.";
    };

    bioHomeserver = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The bio homeserver default copied into new accounts.";
    };

    certTtl = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = "Session certificate lifetime, seconds (default: 7 days).";
    };

    attTtl = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = "Attestation lifetime, seconds (default: 300).";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open the listen port in the firewall.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = (cfg.tlsCert == null) == (cfg.tlsKey == null);
        message = "services.dentrado-auth: tlsCert and tlsKey go together";
      }
      {
        assertion = !hasPrefix (stateDir + "/") cfg.pepper;
        message =
          "services.dentrado-auth: the pepper must live outside ${stateDir} "
          + "(the binary refuses it too — no pepper on the IS disk)";
      }
    ];

    users.users.dentrado-auth = {
      isSystemUser = true;
      group = "dentrado-auth";
    };
    users.groups.dentrado-auth = { };

    systemd.services.dentrado-auth = {
      description = "Dentrado identity service (IS)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        User = "dentrado-auth";
        Group = "dentrado-auth";
        StateDirectory = "dentrado-auth";
        StateDirectoryMode = "0700";
        ExecStart = escapeShellArgs (
          [
            "${cfg.package}/bin/auth"
            "serve"
            "--dir"
            stateDir
            "--bundle"
            cfg.bundle
            "--pepper"
            cfg.pepper
            "--listen"
            cfg.listen
          ]
          ++ optionals (cfg.tlsCert != null) [
            "--tls-cert"
            cfg.tlsCert
            "--tls-key"
            cfg.tlsKey
          ]
          ++ optionals (cfg.host != null) [ "--host" cfg.host ]
          ++ optionals (cfg.webOrigin != null) [ "--web-origin" cfg.webOrigin ]
          ++ optionals (cfg.bioHomeserver != null) [
            "--bio-homeserver"
            cfg.bioHomeserver
          ]
          ++ optionals (cfg.certTtl != null) [ "--cert-ttl" (toString cfg.certTtl) ]
          ++ optionals (cfg.attTtl != null) [ "--att-ttl" (toString cfg.attTtl) ]
        );
        Restart = "on-failure";
        RestartSec = "2s";

        # Sandbox: the whole filesystem read-only except the state
        # dir (StateDirectory), no capabilities, no privileges, no
        # namespaces — the process needs one TCP listener and
        # nothing else (getrandom is a syscall, not a /dev node).
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        Umask = "0077";
      };
    };

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ listenPort ];
  };
}

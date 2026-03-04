{
  description = "BTC-ALPH atomic swaps via MuSig2 adaptor signatures";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        alephium-jar = pkgs.fetchurl {
          url = "https://github.com/alephium/alephium/releases/download/v4.3.1/alephium-4.3.1.jar";
          sha256 = "180v65x2xq650mlhdvn6sxfrjp3sib52fp318w7k7bavpk70q7a2";
        };

        start-regtest = pkgs.writeShellScriptBin "start-regtest" ''
          set -euo pipefail
          DATADIR="$PWD/devnet/bitcoin"
          mkdir -p "$DATADIR"
          cp "$PWD/devnet/bitcoin.conf" "$DATADIR/bitcoin.conf"
          if ${pkgs.bitcoin}/bin/bitcoin-cli -regtest -datadir="$DATADIR" getblockchaininfo &>/dev/null; then
            echo "bitcoind already running"
            exit 0
          fi
          ${pkgs.bitcoin}/bin/bitcoind -regtest -datadir="$DATADIR" -daemon
          echo "bitcoind regtest started (datadir: $DATADIR)"
        '';

        stop-regtest = pkgs.writeShellScriptBin "stop-regtest" ''
          set -euo pipefail
          DATADIR="$PWD/devnet/bitcoin"
          ${pkgs.bitcoin}/bin/bitcoin-cli -regtest -datadir="$DATADIR" stop
          echo "bitcoind regtest stopped"
        '';

        start-devnet = pkgs.writeShellScriptBin "start-devnet" ''
          set -euo pipefail
          ALPHDIR="$PWD/devnet/alephium"
          HOMEDIR="$ALPHDIR/.alephium"
          PIDFILE="$ALPHDIR/alephium.pid"
          mkdir -p "$HOMEDIR"
          cp "$PWD/devnet/alephium.conf" "$HOMEDIR/user.conf"

          if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "alephium devnet already running (pid $(cat "$PIDFILE"))"
            exit 0
          fi

          ${pkgs.openjdk}/bin/java \
            -Xms128m -Xmx512m \
            -Duser.home="$ALPHDIR" \
            -jar ${alephium-jar} \
            &>"$ALPHDIR/alephium.log" &
          echo $! > "$PIDFILE"
          echo "alephium devnet starting (pid $(cat "$PIDFILE"), log: $ALPHDIR/alephium.log)"

          echo -n "waiting for REST API on :22973 "
          for i in $(seq 1 120); do
            if ${pkgs.curl}/bin/curl -sf http://127.0.0.1:22973/infos/self-clique &>/dev/null; then
              echo " ready!"
              exit 0
            fi
            echo -n "."
            sleep 1
          done
          echo " timeout after 120s (check $ALPHDIR/alephium.log)"
          exit 1
        '';

        stop-devnet = pkgs.writeShellScriptBin "stop-devnet" ''
          set -euo pipefail
          PIDFILE="$PWD/devnet/alephium/alephium.pid"
          if [ ! -f "$PIDFILE" ]; then
            echo "no PID file found"
            exit 0
          fi
          PID=$(cat "$PIDFILE")
          if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            echo "alephium devnet stopped (pid $PID)"
          else
            echo "alephium devnet not running (stale pid $PID)"
          fi
          rm -f "$PIDFILE"
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            nodejs_22
            glow
            bitcoin
            openjdk
            jq
	    gh
            curl
            start-regtest
            stop-regtest
            start-devnet
            stop-devnet
          ];

          shellHook = ''
            alias btc='bitcoin-cli -regtest -datadir=$PWD/devnet/bitcoin'
            alias alph='curl -s http://127.0.0.1:22973/'
          '';
        };
      }
    );
}

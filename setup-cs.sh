#!/bin/sh
set -eu

if ! command -v go >/dev/null 2>&1; then
    echo "Go 1.23 is required" >&2
    exit 1
fi

cd "$IVXV/common/tools/go"
go generate ./...
GOBIN="$(pwd)/bin" go install ./...

cd "$IVXV"
common/tools/go/bin/gen -base "$(pwd)" ./common/collector/safereader ./common/collector/cryptoutil ./common/collector/tsp ./common/collector/crypto/elgamal

cd "$IVXV/core/cmd/errorgen"
sh gentmpl.sh gentmpl
go run . -base "$IVXV/core" "$IVXV/core/crypto/asn1" "$IVXV/core/math/polynomial" "$IVXV/core/crypto/elgamal/distributed"

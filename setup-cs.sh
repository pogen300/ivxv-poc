cd "$IVXV/common/tools/go"
go generate ./...
GOBIN="$(pwd)/bin" go install ./...

cd "$IVXV"
common/tools/go/bin/gen -base "$(pwd)" ./common/collector/safereader ./common/collector/cryptoutil ./common/collector/tsp ./common/collector/crypto/elgamal

cd "$IVXV/core/cmd/errorgen"
sh gentmpl.sh gentmpl
go run . -base "$IVXV/core" "$IVXV/core/crypto/asn1" "$IVXV/core/math/polynomial" "$IVXV/core/crypto/elgamal/distributed"
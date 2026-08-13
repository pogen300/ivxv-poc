#!/bin/zsh

export POCROOT="${POCROOT:-$(pwd)}"
export IVXV_POCROOT="${IVXV_POCROOT:-$POCROOT}"
export IVXV="${IVXV:-$POCROOT/repos/ivxv}"
export VVD="${VVD:-$POCROOT/repos/ivotingverification}"

export POC_JAVA_HOME="${POC_JAVA_HOME:-$(/usr/libexec/java_home -v 21 2>/dev/null)}"
export POC_ANDROID_JAVA_HOME="${POC_ANDROID_JAVA_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null)}"

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
export GOCACHE="${GOCACHE:-/tmp/go-build}"
export COMMON_GO_GOBIN="${COMMON_GO_GOBIN:-$IVXV/common/tools/go/bin}"
export COLLECTOR_GOMODCACHE="${COLLECTOR_GOMODCACHE:-$IVXV/common/external/go}"
export GOMODCACHE="${GOMODCACHE:-$COLLECTOR_GOMODCACHE}"
case ":$PATH:" in
  *":$TOOLBIN:"*) ;;
  *) export PATH="$TOOLBIN:$PATH" ;;
esac
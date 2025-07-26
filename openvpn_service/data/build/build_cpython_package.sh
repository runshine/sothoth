#!/bin/bash

set -e
addtional_packges="requests"

ARCH="$(uname -m)"
if [ "$ARCH" = "aarch64" ];then
  URL="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz"
elif [ "$ARCH" = "x86_64" ]; then
  URL="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
fi

if [ "x${ARCH}" = "x" ];then
  echo "unsupport current arch: $ARCH"
  exit 255
fi

download() {
    url=$1
    target=$2
    if [ -f "$target" ];then
      return
    fi
    wget "${url}" -O "$target" || curl "${url}" -o "$target"
    if [ ! -f "$target" ];then
      echo "$(date): file: $target download failed --> $url"
    else
      echo "$(date): file: $target download success"
    fi
}

download "$URL" "cpython.tar.gz"
  if [ -f "cpython.tar.gz" ];then
  tar -zxvf "cpython.tar.gz"
  for package in $addtional_packges
  do
    "./python/bin/pip" install "$package"
  done
else
  echo "download failed"
fi

rm -rf "cpython.tar.gz"
tar -czvf "cpython-linux-$ARCH.tar.gz" python
rm -rf python
if [ ! -d "../package" ];then
  mkdir -p "../package"
fi
mv "cpython-linux-$ARCH.tar.gz" ../package/
echo "done"
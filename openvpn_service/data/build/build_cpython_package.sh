#!/bin/bash

set -e
addtional_packges="requests flask"
ROOT_DIR="$(cd "$(dirname $0)/../";pwd)"

ARCH="$(uname -m)"
if [ "$ARCH" = "aarch64" ];then
  URL="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz"
elif [ "$ARCH" = "x86_64" ]; then
  URL="https://github.com/astral-sh/python-build-standalone/releases/download/20250723/cpython-3.12.11+20250723-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
elif [ "$ARCH" = "armv8l" ] || [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "armv7" ] ; then
#  URL="https://github.com/astral-sh/python-build-standalone/releases/download/20250818/cpython-3.12.11+20250818-armv7-unknown-linux-gnueabihf-install_only.tar.gz"
  if [ -L "/lib/ld-linux.so.3" ] || [ -f "/lib/ld-linux.so.3" ];then
    URL="${ROOT_DIR}/../storage_data/cpython-linux-armel.tar.gz"
  else
    URL="https://github.com/astral-sh/python-build-standalone/releases/download/20250828/cpython-3.12.11+20250828-armv7-unknown-linux-gnueabi-install_only.tar.gz"
  fi
fi

if [ "x${ARCH}" = "x" ] || [ "x${URL}" = "x" ];then
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

if [ -f "$URL" ];then
  cp "$URL" "cpython.tar.gz"
else
  download "$URL" "cpython.tar.gz"
fi

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
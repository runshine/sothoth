#!/usr/bin/env bash
set -Eeuo pipefail

OHEMU_WORKSPACE_ROOT="${OHEMU_WORKSPACE_ROOT:-/workspace/openharmony_6_1}"
OHEMU_SRC_DIR="${OHEMU_SRC_DIR:-${OHEMU_WORKSPACE_ROOT}/vendor/edu/docker/src}"
OHEMU_RUNTIME_ROOT="${OHEMU_RUNTIME_ROOT:-/var/lib/secflow-ipc-audit/ohemu}"

APP="OHEMU"
SUPPORT="mounted OpenHarmony workspace"
PROCESS="${APP,,}"
PROCESS="${PROCESS// /-}"
RUN_LOCAL=1

QEMU_ARCH="${QEMU_ARCH:-${OHEMU_ARCH:-arm64}}"
NETWORK_MODE="${NETWORK_MODE:-${OHEMU_NETWORK_MODE:-bridge}}"
QCOW2_PREPARED_ROOT="${QCOW2_PREPARED_ROOT:-${OHEMU_QCOW2_PREPARED_ROOT:-${OHEMU_WORKSPACE_ROOT}/vendor/edu/docker/volumes/qcow2_cache}}"
STORAGE="${STORAGE:-${OHEMU_RUNTIME_ROOT}/runtime}"
LOG_DIR="${LOG_DIR:-${OHEMU_RUNTIME_ROOT}/logs}"
HDC_BIND="${HDC_BIND:-${OHEMU_HDC_BIND:-127.0.0.1}}"
HDC_BASE_PORT="${HDC_BASE_PORT:-${OHEMU_HDC_BASE_PORT:-55555}}"
HDC_BIN="${HDC_BIN:-${OHEMU_HDC_BIN:-${OHEMU_SRC_DIR}/hdc}}"
HDC_READY_TIMEOUT="${HDC_READY_TIMEOUT:-${OHEMU_HDC_READY_TIMEOUT:-180}}"
HDC_READY_INTERVAL="${HDC_READY_INTERVAL:-${OHEMU_HDC_READY_INTERVAL:-5}}"
WAIT_FOR_HDC_READY="${WAIT_FOR_HDC_READY:-${OHEMU_WAIT_FOR_HDC_READY:-1}}"
VNC_BIND="${VNC_BIND:-${OHEMU_VNC_BIND:-127.0.0.1}}"
VNC_BASE_DISPLAY="${VNC_BASE_DISPLAY:-${OHEMU_VNC_BASE_DISPLAY:-0}}"
INSTANCE_PREFIX="${INSTANCE_PREFIX:-ipc-audit-ohemu}"
QEMU_ACCEL="${QEMU_ACCEL:-${OHEMU_QEMU_ACCEL:-auto}}"
QEMU_AUDIO_DEVICE="${QEMU_AUDIO_DEVICE:-${OHEMU_QEMU_AUDIO_DEVICE:-}}"
RAM_SIZE="${RAM_SIZE:-${OHEMU_RAM_SIZE:-4096M}}"
SMP="${SMP:-${OHEMU_SMP:-6}}"
INSTANCE_NUM="${INSTANCE_NUM:-1}"

usage() {
    cat <<'EOF'
Usage:
  ipc-audit-qemu list
  ipc-audit-qemu ensure [name] [boot_dir|hdc_port] [hdc_port]
  ipc-audit-qemu start [name] [boot_dir|hdc_port] [hdc_port]
  ipc-audit-qemu stop <name>
  ipc-audit-qemu stop-all

This helper starts QEMU directly inside the current secflow-app-ipc-audit
container. It intentionally does not call ohemu-container.sh, docker run,
docker exec, or docker compose.

By default start/ensure wait until hdc can complete a TCP handshake with the
helper-reported endpoint. Set OHEMU_WAIT_FOR_HDC_READY=0 to only start QEMU.

Disk safety:
  QEMU must run on per-instance overlays under OHEMU_RUNTIME_ROOT. The mounted
  prepared qcow2 cache is used only as backing files and must not be written.
EOF
}

fail() {
    printf 'ERROR: %s\n' "${1:-}" >&2
    exit 1
}

require_file() {
    [ -f "$1" ] || fail "required file not found: $1"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

default_sn_for_name() {
    local name=$1
    local digits
    digits="$(printf '%s' "${name}" | md5sum | tr -cd '0-9' | cut -c1-10)"
    while [ "${#digits}" -lt 10 ]; do
        digits="${digits}0"
    done
    printf '%s\n' "${digits}"
}

default_mac_for_name() {
    local name=$1
    local hex
    hex="$(printf '%s' "${name}" | md5sum | cut -c1-10)"
    printf '02:%s:%s:%s:%s:%s\n' \
        "${hex:0:2}" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}"
}

resolve_boot_dir() {
    local normalized_arch=$1
    local kernel_image=$2
    local boot_dir="${OHEMU_BOOT_DIR:-}"

    if [ -z "${boot_dir}" ]; then
        boot_dir="${QCOW2_PREPARED_ROOT}/${normalized_arch}/boot"
    fi
    [ -d "${boot_dir}" ] || fail "boot directory not found: ${boot_dir}"
    [ -f "${boot_dir}/ramdisk.img" ] || fail "missing ramdisk image: ${boot_dir}/ramdisk.img"
    [ -f "${boot_dir}/${kernel_image}" ] || fail "missing kernel image: ${boot_dir}/${kernel_image}"
    printf '%s\n' "${boot_dir}"
}

ensure_overlay_base_images() {
    local base_dir="${QCOW2_PREPARED_ROOT}/${QEMU_ARCH}/base"
    [ -d "${base_dir}" ] || fail "prepared overlay base directory not found: ${base_dir}"
    if ! find "${base_dir}" -maxdepth 1 -type f -name '*.qcow2' | grep -q .; then
        fail "prepared overlay base directory contains no qcow2 files: ${base_dir}"
    fi
}

parse_start_args() {
    START_NAME="${1:-${INSTANCE_PREFIX}-1}"
    START_BOOT_DIR=""
    START_HDC_PORT=""

    if [ $# -ge 2 ]; then
        if [[ "$2" =~ ^[0-9]+$ ]]; then
            START_HDC_PORT="$2"
        else
            START_BOOT_DIR="$2"
            START_HDC_PORT="${3:-}"
        fi
    fi
}

load_ohemu_helpers() {
    require_file "${OHEMU_SRC_DIR}/init.sh"
    require_file "${OHEMU_SRC_DIR}/network.sh"
    require_file "${OHEMU_SRC_DIR}/qemu_common.sh"

    # shellcheck source=/dev/null
    . "${OHEMU_SRC_DIR}/init.sh"
    # shellcheck source=/dev/null
    . "${OHEMU_SRC_DIR}/network.sh"
    # shellcheck source=/dev/null
    . "${OHEMU_SRC_DIR}/qemu_common.sh"
}

preflight_for_start() {
    normalize_arch
    require_cmd "${QEMU_BINARY}"
    require_cmd qemu-img
    require_cmd ss
    if should_wait_for_hdc_ready; then
        require_cmd "${HDC_BIN}"
    fi
    if [ "${NETWORK_MODE,,}" = "bridge" ]; then
        require_cmd brctl
        require_cmd dnsmasq
        require_cmd socat
        [ -c /dev/net/tun ] || fail "bridge mode requires /dev/net/tun in the container"
    fi
    mkdir -p "${STORAGE}" "${LOG_DIR}"
}

should_wait_for_hdc_ready() {
    case "${WAIT_FOR_HDC_READY,,}" in
        0|false|no|off)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

hdc_endpoint_connected() {
    local endpoint=$1

    "${HDC_BIN}" list targets -v 2>/dev/null | awk -v endpoint="${endpoint}" '
        $1 == endpoint && $3 == "Connected" { found = 1 }
        END { exit found ? 0 : 1 }
    '
}

print_hdc_failure_tail() {
    local hdc_log="${HDC_LOG:-/tmp/hdc.log}"

    [ -f "${hdc_log}" ] || return 0
    grep -iE 'libusb|ctxUSB|USB mod|connection reset|failed|error' "${hdc_log}" | tail -n 40 >&2 || true
}

wait_for_hdc_ready() {
    local instance_name=$1
    local state_file
    local endpoint
    local waited=0
    local tconn_output=""

    should_wait_for_hdc_ready || return 0

    state_file="${STORAGE}/state/${instance_name}.env"
    [ -f "${state_file}" ] || fail "instance state file not found: ${state_file}"

    # shellcheck disable=SC1090
    . "${state_file}"
    endpoint="${HDC_BIND}:${HDC_PORT}"

    "${HDC_BIN}" start -r >/dev/null 2>&1 || true

    while [ "${waited}" -le "${HDC_READY_TIMEOUT}" ]; do
        tconn_output="$("${HDC_BIN}" tconn "${endpoint}" 2>&1 || true)"
        if hdc_endpoint_connected "${endpoint}"; then
            printf 'HDC ready: %s\n' "${endpoint}"
            return 0
        fi
        if [ "${waited}" -eq 0 ] || [ $((waited % 30)) -eq 0 ]; then
            printf 'Waiting for HDC endpoint %s (%ss/%ss): %s\n' \
                "${endpoint}" "${waited}" "${HDC_READY_TIMEOUT}" "${tconn_output//$'\n'/ }" >&2
        fi
        sleep "${HDC_READY_INTERVAL}"
        waited=$((waited + HDC_READY_INTERVAL))
    done

    printf 'ERROR: timed out waiting for HDC endpoint %s after %ss\n' "${endpoint}" "${HDC_READY_TIMEOUT}" >&2
    print_hdc_failure_tail
    return 1
}

start_or_reuse_instance() {
    local reuse=$1
    shift || true

    parse_start_args "$@"
    preflight_for_start

    local boot_dir="${START_BOOT_DIR:-}"
    if [ -z "${boot_dir}" ]; then
        boot_dir="$(resolve_boot_dir "${QEMU_ARCH}" "${OHOS_KERNEL_IMAGE}")"
    fi
    ensure_overlay_base_images

    if [ "${reuse}" = "1" ] && instance_is_running "${START_NAME}"; then
        printf 'Reusing %s\n' "${START_NAME}"
        printf 'Overlay root: %s/%s\n' "${INSTANCE_DIR}" "${START_NAME}"
        list_instances
        wait_for_hdc_ready "${START_NAME}"
        return 0
    fi

    local sn="${OHEMU_INSTANCE_SN:-$(default_sn_for_name "${START_NAME}")}"
    local mac="${OHEMU_INSTANCE_MAC:-$(default_mac_for_name "${START_NAME}")}"
    start_instance "${START_NAME}" "${boot_dir}" "${sn}" "${mac}" "${START_HDC_PORT}" ""
    printf 'Overlay root: %s/%s\n' "${INSTANCE_DIR}" "${START_NAME}"
    list_instances
    wait_for_hdc_ready "${START_NAME}"
}

load_ohemu_helpers

cmd="${1:-list}"
shift || true

case "${cmd}" in
    list)
        normalize_arch
        mkdir -p "${STORAGE}" "${LOG_DIR}"
        list_instances
        ;;
    ensure)
        start_or_reuse_instance 1 "$@"
        ;;
    start)
        start_or_reuse_instance 0 "$@"
        ;;
    stop)
        [ $# -eq 1 ] || { usage; exit 2; }
        stop_instance "$1"
        ;;
    stop-all)
        stop_all_instances
        ;;
    *)
        usage
        exit 2
        ;;
esac

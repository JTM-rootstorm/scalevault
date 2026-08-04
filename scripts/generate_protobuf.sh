#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly tools_directory="${repository_root}/tools"
readonly proto_directory="${repository_root}/proto"
readonly checked_in_directory="${repository_root}/gen/relay/v1"
readonly generated_module="github.com/JTM-rootstorm/scalevault/gen/relay"
readonly generated_files=("relay-v1.pb.go" "relay-v1_grpc.pb.go")
readonly go_build_cache="${GOCACHE:-${repository_root}/.cache/go-build}"
readonly go_module_cache="${GOMODCACHE:-${repository_root}/.cache/go-mod}"
readonly required_protoc_version="libprotoc 31.1"
readonly required_go_generator_version="protoc-gen-go v1.36.11"
readonly required_go_grpc_generator_version="protoc-gen-go-grpc 1.6.2"

usage() {
    echo "usage: $0 --check|--write" >&2
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

readonly mode="$1"
if [[ "${mode}" != "--check" && "${mode}" != "--write" ]]; then
    usage
    exit 2
fi

readonly temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/scalevault-protobuf.XXXXXX")"
trap 'rm -rf -- "${temporary_directory}"' EXIT

readonly generator_directory="${temporary_directory}/bin"
mkdir -p "${generator_directory}"

actual_protoc_version="$(protoc --version)"
if [[ "${actual_protoc_version}" != "${required_protoc_version}" ]]; then
    echo "protoc version mismatch: expected ${required_protoc_version}, got ${actual_protoc_version}" >&2
    exit 1
fi

GOWORK=off GOCACHE="${go_build_cache}" GOMODCACHE="${go_module_cache}" \
    go -C "${tools_directory}" build -trimpath -buildvcs=false \
    -o "${generator_directory}/protoc-gen-go" \
    google.golang.org/protobuf/cmd/protoc-gen-go
GOWORK=off GOCACHE="${go_build_cache}" GOMODCACHE="${go_module_cache}" \
    go -C "${tools_directory}" build -trimpath -buildvcs=false \
    -o "${generator_directory}/protoc-gen-go-grpc" \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc

actual_go_generator_version="$("${generator_directory}/protoc-gen-go" --version)"
actual_go_grpc_generator_version="$("${generator_directory}/protoc-gen-go-grpc" --version)"
if [[ "${actual_go_generator_version}" != "${required_go_generator_version}" ]]; then
    echo "generator version mismatch: expected ${required_go_generator_version}, got ${actual_go_generator_version}" >&2
    exit 1
fi
if [[ "${actual_go_grpc_generator_version}" != "${required_go_grpc_generator_version}" ]]; then
    echo "generator version mismatch: expected ${required_go_grpc_generator_version}, got ${actual_go_grpc_generator_version}" >&2
    exit 1
fi

generate_into() {
    local output_directory="$1"
    mkdir -p "${output_directory}"
    protoc \
        --proto_path="${proto_directory}" \
        --plugin="protoc-gen-go=${generator_directory}/protoc-gen-go" \
        --plugin="protoc-gen-go-grpc=${generator_directory}/protoc-gen-go-grpc" \
        --go_out="${output_directory}" \
        --go_opt="module=${generated_module}" \
        --go-grpc_out="${output_directory}" \
        --go-grpc_opt="module=${generated_module}" \
        "${proto_directory}/relay-v1.proto"
}

readonly first_output="${temporary_directory}/first"
generate_into "${first_output}"

if [[ "${mode}" == "--write" ]]; then
    mkdir -p "${checked_in_directory}"
    for generated_file in "${generated_files[@]}"; do
        install -m 0644 \
            "${first_output}/v1/${generated_file}" \
            "${checked_in_directory}/${generated_file}"
    done
    echo "regenerated ${#generated_files[@]} protobuf Go files"
    exit 0
fi

readonly second_output="${temporary_directory}/second"
generate_into "${second_output}"

status=0
for generated_file in "${generated_files[@]}"; do
    first_file="${first_output}/v1/${generated_file}"
    second_file="${second_output}/v1/${generated_file}"
    checked_in_file="${checked_in_directory}/${generated_file}"

    if ! cmp -s "${first_file}" "${second_file}"; then
        echo "protobuf generation is not deterministic: ${generated_file}" >&2
        status=1
    fi
    if [[ ! -f "${checked_in_file}" ]] || ! cmp -s "${first_file}" "${checked_in_file}"; then
        echo "stale protobuf output: ${checked_in_file}" >&2
        status=1
    fi
done

checked_in_files=("${checked_in_directory}"/*.pb.go)
if [[ ${#checked_in_files[@]} -ne ${#generated_files[@]} ]]; then
    echo "unexpected protobuf Go files exist under ${checked_in_directory}" >&2
    status=1
fi

if [[ ${status} -ne 0 ]]; then
    echo "run scripts/generate_protobuf.sh --write and review the generated diff" >&2
    exit "${status}"
fi

echo "verified deterministic, current protobuf Go outputs"

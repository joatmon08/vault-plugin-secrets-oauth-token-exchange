#!/usr/bin/env bash
# Copyright IBM Corp. 2026
# SPDX-License-Identifier: MPL-2.0

set -e

PLUGIN_DIR=$1
PLUGIN_NAME=$2
PLUGIN_PATH=$3

# Enable the plugin
vault plugin register \
    -sha256=$(shasum -a 256 "${PLUGIN_DIR}/${PLUGIN_NAME}" | awk '{print $1}') \
    -command="${PLUGIN_NAME}" \
    secret \
    "${PLUGIN_NAME}"

# Mount the plugin
vault secrets enable -path="${PLUGIN_PATH}" "${PLUGIN_NAME}"

echo "Plugin registered and mounted at ${PLUGIN_PATH}"

# Made with Bob

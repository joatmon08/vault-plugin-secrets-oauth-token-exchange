#!/bin/bash
# Copyright IBM Corp. 2026
# SPDX-License-Identifier: MPL-2.0


source secrets.env

vault delete sts/role/second-client
vault delete sts/role/test-client
vault delete sts/key/test
vault delete sts/config
vault secrets disable sts
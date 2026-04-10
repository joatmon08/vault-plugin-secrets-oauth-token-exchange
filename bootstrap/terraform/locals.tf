# Copyright IBM Corp. 2026
# SPDX-License-Identifier: MPL-2.0

locals {
  end_user = "end-user"
  client_agents = {
    "test-client" = {
      "scope" : "helloworld:read"
    },
    "second-client" = {
      "scope" : "helloworld:read"
    }

  }
}
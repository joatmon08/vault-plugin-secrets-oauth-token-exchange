locals {
  end_user = "end-user"
  client_agents = {
    "test-client" = {
      "scopes" : "helloworld:read"
    },
    "second-client" = {
      "scopes" : "helloworld:read"
    }

  }
}
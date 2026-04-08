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
#!/bin/bash

source secrets.env

vault delete sts/role/second-client
vault delete sts/role/test-client
vault delete sts/key/test
vault delete sts/config
vault secrets disable sts
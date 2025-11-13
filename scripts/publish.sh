#!/bin/bash

required_vars=("NPM_TOKEN" "GITHUB_TOKEN")

check_env_vars() {
  local vars=("$@")
  for var_name in "${vars[@]}"; do
    if [ -z "${!var_name}" ]; then
      echo "Error: $var_name is not set."
      exit 1
    fi
  done
}

check_env_vars "${required_vars[@]}"

echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc

if ! pnpm can-npm-publish; then
  echo "This package cannot be published, as this version already exists."
  exit 0
fi

pnpm publish --access public --no-git-checks

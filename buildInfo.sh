#! /bin/bash
# generates the build information to populate the version metric
BIN_NAME="POPS"

if [ -z  "$COMMIT_SHA" ]; then
  COMMIT_SHA=$(git log -n1 --pretty=format:%H)
fi

if [ -z  "$BIN_VERSION" ]; then
  BIN_VERSION="1.0-SNAPSHOT"
fi

if [ -z "$BUILDER" ]; then
    BULIDER="Makefile"
fi

echo "{
    \"name\": \"$BIN_NAME\",
    \"version\": \"$BIN_VERSION\",
    \"builder\": \"$BUILDER\",
    \"commit\": \"$COMMIT_SHA\"
}" > buildInfo.json
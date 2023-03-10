#!/bin/sh

## bump.sh
# This script bumps the version number of the package.json and
# adds the changes (package.json and package-lock.json) to the staging area.

# get latest commit message
commit_msg=$(git log -1 --pretty=%B)
echo "[bump.sh] commit message: $commit_msg"

# exit with success if the commit message is empty
if [ -z "$commit_msg" ]; then
  echo "[bump.sh] no commit message found."
  exit 0
fi

# exit with success if the commit message is a merge
if echo "$commit_msg" | grep -qE '^Merge'; then
  echo "[bump.sh] commit message is a merge."
  exit 0
fi

# exit with success if the commit message has already been bumped
# by checking for the presence of a version number in square brackets
if echo "$commit_msg" | grep -qE '\[[0-9]+\.[0-9]+\.[0-9]+\]'; then
  echo "[bump.sh] commit message already bumped."
  exit 0
fi

# determine the version type
if echo "$commit_msg" | grep -qE '^(feature|config):'; then
  version_type="minor"
elif echo "$commit_msg" | grep -qE '^(patch|fix):'; then
  version_type="patch"
else
  echo "[bump.sh] no version bump needed."
  exit 0
fi

# bump version and update package.json
npm version $version_type --no-git-tag-version

# get the new version number
version=$(node -p "require('./package.json').version")

# stage changes to the staging area
git add package.json package-lock.json

# add [$version] to the beginning of the commit message
new_commit_msg="[$version] $commit_msg"

# ammend changes to the latest commit
# note: `--no-verify` is used to skip the pre-commit hook which lints and tests the code
# note: `-q` is used to suppress the output of the command
git commit --amend --no-edit --no-verify -q -m "$new_commit_msg"

# exit with success status
echo "[bump.sh] version bump to $version_type [$version]"
exit 0

#!/bin/bash

# Get the current branch name
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Get the current version number
VERSION=$(node -p "require('./package.json').version")

# Increment the version number using semver (e.g. 1.2.3 => 1.2.4)
NEW_VERSION=$(npm version patch --no-git-tag-version)

# Update the version number in package.json
npm --no-git-tag-version version $NEW_VERSION --allow-same-version

# Add the changes to git
git add package.json
git add package-lock.json

# Get the current commit message and append the new version number on a new line
OLD_COMMIT_MESSAGE=$(git log --format=%B -n 1 HEAD)$'\n'$'\n'
NEW_VERSION_MESSAGE="Bumped version to $NEW_VERSION"
NEW_COMMIT_MESSAGE="$OLD_COMMIT_MESSAGE$NEW_VERSION_MESSAGE"


# Check if the previous commit has been pushed
if git log origin/$BRANCH..HEAD >/dev/null 2>&1; then
  # Previous commit has been pushed, create a new commit
  git commit -m "$NEW_COMMIT_MESSAGE"
else
  # Previous commit hasn't been pushed, amend it with the new version number
  git commit --amend -m "$NEW_COMMIT_MESSAGE" --no-edit
fi

# Get the entire commit message including the body
COMMIT_MESSAGE=$(git log --format=%B -n 1 HEAD)
echo "$COMMIT_MESSAGE"
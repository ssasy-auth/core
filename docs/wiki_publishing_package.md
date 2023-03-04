# Package Management

## Publishing a package

Pre-requisites:

- Skim through this [GitHub guide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry#publishing-a-package-using-a-local-npmrc-file) for publishing packages to GitHub's package registry.
- [Setup GitHub token](https://github.com/settings/tokens) with `repo` and `read:packages` permissions.

### `.npmrc` file setup

```ini
# set scope
@NAMESPACE:registry=https://npm.pkg.github.com

# add github token (replace TOKEN with your token)
//npm.pkg.github.com/:_authToken=TOKEN
```

1. create a `.npmrc` file in the root of your project.
2. replace `NAMESPACE` with your GitHub username and `TOKEN` with the GITHUB_TOKEN you created.

### npm command line setup

1. run `npm login --scope=@NAMESPACE --auth-type=legacy --registry=https://npm.pkg.github.com` where `NAMESPACE` is your GitHub username.
2. enter your username and the GITHUB_TOKEN you created as the password.
3. run `npm publish` to publish the package.

## Installing a package

```ini
# set scope
@NAMESPACE:registry=https://npm.pkg.github.com

# add github token (replace TOKEN with your token)
//npm.pkg.github.com/:_authToken=TOKEN
```

> .npmrc file setup

```json
{
  "dependencies": {
    "@NAMESPACE/PACKAGE_NAME": "VERSION"
  }
}
```

1. create a `.npmrc` file in the root of your project
2. replace `NAMESPACE` with your GitHub username and `TOKEN` with the GITHUB_TOKEN you created.
3. add the package you want to install to your `package.json` file under `dependencies` or `devDependencies`. 
   1. replace `NAMESPACE` with your GitHub username and `PACKAGE_NAME` with the name of the package you want to install. 
   2. replace `VERSION` with the version of the package you want to install.
4. run `npm install` to install the package.

## Something to consider

NPM offers free hosting for open source (a.k.a public) packages, however, users must upgrade to a paid plan if they want to host private packages. GitHub, on the other hand, offers free hosting for both public and private packages which is great for my use case - developing a proof of concept for my novel thesis project. However, the goal is to eventually publish the package to NPM so that it can be used by other developers.

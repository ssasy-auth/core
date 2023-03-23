# package management

> a note on publishing as a private package:
>
>although NPM offers free hosting for open source (a.k.a public) packages, users must upgrade to a paid plan if they want to host private packages. GitHub, on the other hand, offers free hosting for both public and private packages.
>
> My usecase (thesis) requires that I develop a proof of concept for my thesis project. Since my thesis is scanned for plagiarism, I don't want to publish the package to NPM because it would be publicly available and accessible to the web crawlers that scan for plagiarism.
>
>That being said, the goal is to eventually publish the package to NPM so that it can be used by other developers.

## sumary

This is a quick guide for publishing packages to GitHub's package registry.

## publishing a package

Pre-requisites:

- Skim through this [GitHub guide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry#publishing-a-package-using-a-local-npmrc-file) for publishing packages to GitHub's package registry.
- [Setup GitHub token](https://github.com/settings/tokens) with `repo` and `read:packages` permissions.

### `.npmrc` file setup

```ini
# set scope
@NAMESPACE:registry=https://npm.pkg.github.com

# note: set github token in your environment variables by running
# `echo "export GITHUB_TOKEN=<insert-github-token-here>" >> ~/.zshenv
# so that it is available in your shell
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

1. create a `.npmrc` file in the root of your project.
2. replace `NAMESPACE` with your GitHub username and `TOKEN` with the GITHUB_TOKEN you created.

### npm command line setup

1. run `npm login --scope=@NAMESPACE --auth-type=legacy --registry=https://npm.pkg.github.com` where `NAMESPACE` is your GitHub username.
2. enter your username and the GITHUB_TOKEN you created as the password.
3. run `npm publish` to publish the package.

### publishing Typescript packages

Typescript packages are not executable on their own so they need to be compiled into Javascript before they can be published which requires a few extra steps compared to publishing a Javascript package. That being said, you need to:

1. `tsc` - build the package into Javascript
2. `npm publish` - publish the package to NPM

If you want to expose your projects types (e.g. interfaces, enums, etc.) to other projects, you need to configure your tsconfig.json file to do so. This includes:

```json
{
  "compilerOptions": {
    "declaration": true, // enable declaration files
    "declarationMap": true, // enable sourcemaps for declaration files
  }
}
```

## installing a package

```ini
# set scope
@NAMESPACE:registry=https://npm.pkg.github.com

# note: set github token in your environment variables by running
# `echo "export GITHUB_TOKEN=<insert-github-token-here>" >> ~/.zshenv
# so that it is available in your shell
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
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
   - replace `NAMESPACE` with your GitHub username and `PACKAGE_NAME` with the name of the package you want to install.
   - replace `VERSION` with the version of the package you want to install.
4. run `npm install` to install the package.

## testing package locally

At this point you should be able to publish the package to GitHub's package registry. However, if you are a clumsy developer like me, you may want to test the package locally before publishing it to NPM. To do this, there are two ways to go about this:

### packaging the package

This is the simplest way to go about this. You can package the package using the `npm pack` command.

```bash
# package the package (note: this will create a .tgz file in the root of the project)
npm pack

# in the project where you want to use the package, install the package
npm install 'PATH/TO/THE/TGZ/FILE'

# uninstalling the package
npm uninstall 'PACKAGE_NAME'
```

### linking the package

Following this [article](https://flaviocopes.com/npm-local-package/), you can create a link to the package using the `npm link` command.

```bash
# create a link to the package
npm link

# in the project where you want to use the package, install the 'linked' package
npm install 'LINKED_PACKAGE_NAME'

# uninstalling the 'linked' package (see https://stackoverflow.com/questions/19094630/how-do-i-uninstall-a-package-installed-using-npm-link)

sudo npm rm --global 'LINKED_PACKAGE_NAME'

# check that the package is uninstalled
npm list -g --depth=0
```

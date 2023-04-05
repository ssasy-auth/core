# `ssasy` contribution

This document is intended to help you get started with contributing to `ssasy`.

## principles

The goal of this project is to create a usable and secure user authentication system. In order to acheive this, the source code needs to be maintainable and easy to understand. To acheive this, the following principles are followed:

- **secure** - it is easier said than done, but security should be a top priority. You should be able to explain why your code is secure *or* why it is not. Feel free to ask for help if you are unsure about something.
- **simple > complex** - the source code should be simple and easy to understand. This means no one-letter variable names, no clever tricks and no over-engineering. If you are unsure if your code is simple enough, ask yourself if you could explain it to a ~5 year old~ bachelor student.
- **dont repeat yourself** - don't repeat yourself. If you find yourself copy-pasting code, you are probably doing something wrong. Instead, try to find a way to abstract the common functionality into a function or class. This will make the code easier to understand, test and maintain.
- **test code** - at the very least, changes should be tested so that they a) produce the intended result and b) don't break existing functionality. If you are unsure how to test your code, feel free to ask for help.

## project structure

At a high level, the project is structured as follows:

- `tests/` - contains the tests for the project
- `src/` - project source code
  - `config/` - project configuration
  - `interfaces/` - typescript interfaces
  - `modules/` - the modules that make up the project
    - `challenge-mod.ts` - creating and verifying challenges
    - `crypto-mod.ts` - cryptographic operations
    - `encoder-mod.ts` - encoding and decoding data
    - `key-mod.ts` - key operations
    - `indext.ts` - entry point for the module
  - `utils/` - contains utility or plugins that are used by the project
  - `wallet.ts` - contains the wallet class for the project
  - `index.ts` - contains the entry point for the project


## getting started

Jumping into brand new source code can be daunting so feel free to read the [architecture document](../designs/architecture.md) to get a better understanding of the project structure.

Also, this project uses `pnpm` as its package manager. To get started, run the following commands:

```bash
# install pnpm
npm install -g pnpm

# install project dependencies
pnpm install
```

## proposing changes

If you want to propose a change, you can do so by creating a [pull request](https://github.com/this-oliver/ssasy/pulls) or by creating an [issue](https://github.com/this-oliver/ssasy/issues). If you are unsure about something, feel free to ask for help.

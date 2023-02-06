# Self-Sovereign Authentictaion Scheme (SSASy)

> To be sovereign is to have supreme power and to be free from external control or influence ([Merriam-Webster](https://www.merriam-webster.com/dictionary/sovereign)).

SSASy is a self-sovereign authentication scheme that enables users to authenticate themselves in usable, secure and decentralized manner without without relying on a third party (e.g. Google, Microsoft, Facebook, Twitter). The scheme is based on two main concepts: (1) [Public Key Encryption](https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/diffie-hellman.pdf) by Diffie and Hellman and (2) the [Self-Sovereign Identity](http://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html) by Chirstopher Allen.

## Table of Contents

- [Self-Sovereign Authentictaion Scheme (SSASy)](#self-sovereign-authentictaion-scheme-ssasy)
  - [Table of Contents](#table-of-contents)
  - [Motivation](#motivation)
    - [Usability](#usability)
    - [Security](#security)
    - [Problem Statement](#problem-statement)
  - [How it works](#how-it-works)
    - [Setup](#setup)
    - [Register](#register)
    - [Authenticate](#authenticate)
    - [Recover](#recover)
    - [Transfer](#transfer)
    - [Delegate](#delegate)
  - [Installation](#installation)
  - [Usage](#usage)
  - [License](#license)

## Motivation

There are two main problems with the current authentication schemes (AS) on the web.

### Usability

> '_The more secure you make something, the less secure it becomes_' - [Don Norman](https://jnd.org/when_security_gets_in_the_way)

Nowadays, users have multiple accounts for different services (Twitter, Instagram, LinkedIn, Banking etc.) and, according to security best practices, they ought to create strong passwords with a combination of character types and at least 8 characters long for each account. This is cognitively demanding, time consuming and inconvenient which usually causes users to:

- create weak passwords,
- reuse passwords accrross multiple accounts, and
- forget their passwords.

Put simply, users will find ways to streamline repetative tasks that are not meaningful to them.

Ofcourse, there are other ways to authenticate users but these methods are not always available and have raised privacy concerns. For example, authenticating with biometrics (fingerprints, facescan) usually requires the user to (a) have a device that has a biometric scanner and (b) upload their biometric data to the service provider.

### Security

Another problem with contemporary AUs is that users rely on services and federated identity (FI) providers (e.g. Google, Microsoft, Facebook, Twitter) to authenticate their identities. This has four implications, to name a few:

- if services or FI providers are hacked, users' data is compromised,
- if services or FI providers go out of business, users' data is lost,
- if an FI provider decided to ban or suspend users, the users no longer have access to the services or their data, and
- many platforms do not allow users to change their FI providers which means that users are locked in to a particular FI provider

The points mentioned above are not just theoretical. One [VPN provider exposed millions of logs](https://www.comparitech.com/blog/vpn-privacy/ufo-vpn-data-exposure/) containing account passwords (clear text) and other sensitive information belonging to its 20 million users. A number of [journalists on Twitter were banned](https://techcrunch.com/2022/12/15/twitter-just-banned-a-wave-of-prominent-journalists-with-no-explanation/) for covering Elon Musk during his takeover of the social media platform. A [father was banned from his Google account](https://www.nytimes.com/2022/08/21/technology/google-surveillance-toddler-photo.html) for taking a photo of his toddler daughter for a doctor. The ban also meant that he was unable to access the services linked to the account which exacerbate his situation.

Solving this problem also means that service providers no longer have to store users' authentication data (e.g. passwords, biometric data) which is a huge security risk.

On top of the reliance to third parties, users are exposed to a number of security threats on the internet - the most prominent being phishing scams whereby users enter their identitifier and password into websites that are impersonating legitimate services (e.g. goooogle.com, a phishing website, impersonates google.com, a legitimate platform).

At the end of the day, users are unable to use AS, as they were intended, so the users take shortcuts that render the AS inneffective. Even when users do everything right, they are still vulnerable if the services and FI providers that they rely on become compromised.

### Problem Statement

User authentication is a very important aspect of the internet and involves a number of stakeholders, the most important being the user (claimant) that needs to authenticate themselves and the service or platform (verifier) that needs to ensure that only authorized users are able to access some resources.

One possible solution would be an authentication scheme that enable users to be self-sovereign in how they authenticate themselves. The AS should also be secure to the same extent as existing solutions otherwise it won't be adopted by existing infrastructures. Lastly, the AS should be usable - this is very important given that the self-sovereign aspect implies that users are in control of their authentication as opposed to a digital platform with much larger resource pools. Usability, or perceived ease of use, is also important when considering user adoption in the context of innovative technologies.

> '_Any system that puts control in the hands of end-users carries the burden of education, both for the well-functioning of the system as well as for safeguarding its role in protecting the public interest_' - [Goodell and Aste](https://www.frontiersin.org/articles/10.3389/fbloc.2019.00017/full)

In order to acheive this, the self-sovereign authentication scheme should be able to possess the following features:

1. the claimant and verifier should be able to understand and manage the scheme such that they know how it works and are aware of the threat landscapes,
2. inter-operability, such that the claimant is able to authenticate with different verifiers using the same authenticator instance,
3. the claimant and verifier should be able to recover their authenticator if it were to be forgoten or lost
4. the claimant and verifier should be able to delegate their tasks without sharing credentials so that security is not compromised at the cost of productivity

These features are still in progress and succesptible to change.

## How it works

### Setup

### Register

### Authenticate

### Recover

### Transfer

### Delegate

## Installation

## Usage

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file, in the root of the project, for details.

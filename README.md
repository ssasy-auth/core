# **_SSASy_**

> To be sovereign is to have supreme power and to be free from external control or influence ([Merriam-Webster](https://www.merriam-webster.com/dictionary/sovereign)).

SSASy is a **self-sovereign authentication scheme** that enables users to authenticate themselves in usable, secure and decentralized manner without without relying on a third party (e.g. Google, Microsoft, Facebook, Twitter). The scheme is based on two main concepts: (1) [Public Key Encryption](https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/diffie-hellman.pdf) by Diffie and Hellman and (2) the [Self-Sovereign Identity](http://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html) by Chirstopher Allen.

---

## Table of Contents

- [**_SSASy_**](#ssasy)
  - [Table of Contents](#table-of-contents)
  - [**Introduction**](#introduction)
    - [Usability](#usability)
    - [Security](#security)
    - [Problem Statement](#problem-statement)
  - [**How it works**](#how-it-works)
    - [Registration](#registration)
    - [Authentication](#authentication)
    - [Recovery](#recovery)
    - [Delegation](#delegation)
  - [**Usage**](#usage)
    - [Core Logic](#core-logic)
    - [Client Library](#client-library)
  - [**License**](#license)

## **Introduction**

User authentication is a foundational building block on the Internet and in Information Security because ensures that information and services are only accessed by authorized users. Almost all websites on the internet require users to register and authenticate themselves before they can access their emails, social media or financial services. However, there are two main problems with the current authentication schemes (AS) on the web.

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

User authentication is a very important aspect of the internet and involves a number of stakeholders, the most important being the user (**claimant**) that needs to authenticate themselves and the service or platform (**verifier**) that needs to ensure that only authorized users are able to access some resources.

One possible solution would be an authentication scheme that enable users to be self-sovereign in how they authenticate themselves. The AS should also be secure to the same extent as existing solutions otherwise it won't be adopted by existing infrastructures. Lastly, the AS should be usable - this is very important given that the self-sovereign aspect implies that users are in control of their authentication as opposed to a digital platform with much larger resource pools. Usability, or perceived ease of use, is also important when considering user adoption in the context of innovative technologies.

> '_Any system that puts control in the hands of end-users carries the burden of education, both for the well-functioning of the system as well as for safeguarding its role in protecting the public interest_' - [Goodell and Aste](https://www.frontiersin.org/articles/10.3389/fbloc.2019.00017/full)

In order to acheive this, the self-sovereign authentication scheme should be able to possess the following features:

1. the claimant and verifier should be able to understand and manage the scheme such that they know how it works and are aware of the threat landscapes,
2. inter-operability, such that the claimant is able to authenticate with different verifiers using the same authenticator instance,
3. the claimant and verifier should be able to recover their authenticator if it were to be forgoten or lost
4. the claimant and verifier should be able to delegate their tasks without sharing credentials so that security is not compromised at the cost of productivity

_Note: These features are still in progress and succesptible to change._

---

## **How it works**

At a very high level, the self-sovereign authentication scheme (SSASy) is a two-party authentication scheme that uses a **claimant** and a **verifier**. The claimant is the user that needs to authenticate themselves and the verifier is the service or platform that needs to ensure that only authorized users are able to access some resources.

Using public key cryptography, SSASy is able to provide a seamless and secure authentication experience for the users. The following is a generic sequence of events that would occur during the authentication process:

### Registration

1. the claimant generates a public/private key pair
2. the claimant registers their public key with the verifier (e.g. Twitter)
3. the verifier stores the public key and binds it to the claimant's account along with additional metadata (e.g. username, email)
4. the claimant receives a confirmation from the verifier along with the verifier's public key which the claimant stores

### Authentication

1. the claimant provides an identitifer (e.g. public key, username, email) to the verifier
2. the verifier extracts the public key from the claimant's account and sends a challenge (e.g. a nonce encrypted with the public key) to the claimant
3. the claimant decrypts the challenge with their private key and signs the challenge with their private key. Afterwards, the claimant encrypts the signature with the verifier's public key and sends it back to the verifier
4. the verifier decrypts the signature with the verifier's private key and verifies that the signature is valid. If the signature is valid, the verifier authenticates the claimant and grants the claimant access to the resources (e.g. using an access token).

### Recovery

<!--TODO-->

### Delegation

<!--TODO-->

---

## **Usage**

At a high level, SSASy is made up of two main components; (1) the core logic and (2) the client library that would be used by claimants and verifier.

### Core Logic

The core logic is responsible for all the cryptographic operations that are required for the scheme to work. Both, the server and client libraries, depend on the core logic to perform their respective tasks.

Functions:

- [ ] generate public key pair
- [ ] encrypt and decrypt data
- [ ] create and verify signatures
- [ ] challenge and response

Stack:

- [Rust](https://www.rust-lang.org/)

### Client Library

The client library is meant to be used by the claimant to create their public key pair, register and authenticate with the verifier, among other things. Although the verifier is different from the claiment, in the context of an registration and authentication dance, they both perform similar tasks. Therefore, the client library is also used by the verifier.

Functions:

- [ ] **general**
  - [ ] create a key pair
  - [ ] setup recovery option
  - [ ] setup delegation option
- [ ] **claimant**
  - [ ] register to a verifier
  - [ ] authenticate with a verifier
- [ ] **verifier**
  - [ ] register a claimant
  - [ ] authenticate a claimant

Stack:

- [Vue.js](https://vuejs.org/) for the web client
- [Python](https://www.python.org/) for the CLI client

---

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file, in the root of the project, for details.

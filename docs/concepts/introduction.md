# why use self-sovereign authentication schemes?

`Self-sovereign authentication schemes`, use [public key cryptography](./encryption.md) to address security risks that are associated with user authentication for two stakeholders:

- `user` - (*a.k.a the `claimant`*) the person that needs to register and login into one or more services
- `service` - (*a.k.a the `verifier`*) the website or platform that needs to verify the identity of the user before granting access to a resource

## improving security for services

In order to verify the identity of a user, services need to store the user's `password`[^1] in a database. That way, whenever the user wants to login, the service can compare the password that the user provides with the password that is stored in the database.

One of the most common security risks for a service is that the password is leaked. This can happen in many ways (e.g. a database backup is leaked, a developer accidentally leaks the password in a commit, etc). Leaked passwords can be used to impersonate users and gain access to the service. The leaked passwords can also be used to gain access to the user's other services if they reuse the same password.

Another common security risk is that hackers will create websites that look like the real service and trick users into entering their email and password. This is called a `phishing attack`. Once the user enters their details, the hacker can use the password to login into the real service and gain access to the user's account.

With self-sovereign authentication schemes:

- the service does not store the user's password. Instead, they store the user's `public key` which they can use to verify the identity of the user through challenge-response authentication. This reduces the impact of a data leak because the leaked data (e.g. public key) is not sensitive information and can be safely shared with anyone.

- phishing attacks no longer work in the sense that the hacker cannot use the public key to impersonate the user without also managing to retreive the user's `private key` which is never shared with the service.

## improving security for users

Security best-practises recommend that passwords should be hard-to-guess **and** unique for each service. This is difficult for a user to achieve because they probably use around 11+ services which means that they need to remember 11+ passwords that are unqiue and hard-to-guess which is not practical and coginitively expensive.

One of the most common security risks for a user is that they create simple passwords (e.g. 'password', '123456', etc) because they are easy to remember. Hackers can run tools that guess passwords using common words, numbers and passwords that have been leaked in the past. If the hacker guesses the password correctly, they can use it to login into the service and gain access to the user's account.

Another common security risk is that users reuse the same password for multiple services. This means that if one of their services is compromised, the attacker can use the same password to login into other services.

With self-sovereign authentication schemes, users are introduced to [public key encryption](./encryption.md) which allows them to use their public keys to identify themselves to services and their private keys to sign into services. This means that:

- users only have to invest effort in creating a single password that is hard-to-guess. This is beacuse the password is only used to encrypt their private key which is then used to sign into their services.
- password reuse is no longer a problem because the user's private key is never shared with the service. This means that even if the user's service is compromised, the attacker cannot use the private key to impersonate the user.

[^1]: Although 'passwords' are used as an example, the same concept applies to almost any type of secret that is used to authenticate a user except for public keys.

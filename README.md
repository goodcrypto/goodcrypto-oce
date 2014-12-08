#goodcrypto_oce - GoodCrypto OCE

GoodCryptoOpen Crypto Engine (OCE) provides a common API to crypto engines such as GPG, PGP, and Bouncy Castle. Because the crypto is pluggable, you can instantly switch underlying crypto packages. Using a single API, you can even nest encryption by different packages. If just one of the crypto packages is secure, so is your message. To use nested encryption you may need an OCE application at both ends.

OCE is intended primarily for OpenPGP email and file encryption. It uses some library classes from GoodCrypto.


##Introduction

There are 2 implementations of OCE: one in python and the other in java. The python branch is being actively maintained.


##Dependencies

The python implementation requires the goodcrypto-libs repository.



##Kudos

Thanks to the authors and contributors of gpg, openssl, debian, and all the other open source projects which GoodCrypto uses.


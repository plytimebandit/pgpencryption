# PGP Encryption

![build-status](https://github.com/plytimebandit/pgpencryption/actions/workflows/maven.yml/badge.svg)

This PGP encryption tool can be used to encrypt and decrypt files.

I tried to keep it simple.
Just build the jar by executing e.g. `./mvnw clean verify`
(the unit tests might take a while, so you might want to skip them)
and run the jar by executing `java -jar pgpencryption-1.0-SNAPSHOT-jar-with-dependencies.jar`.
This will show you the usage.

There are just three scenarios:

- create keys
- encrypt file
- decrypt file

That's it. Have fun.


## Further information

### Java version

JDK 8 is necessary to run this tool.


### Maven Toolchain

You need a [toolchain](https://maven.apache.org/guides/mini/guide-using-toolchains.html#using-toolchains-in-your-project) with a `jdk` in version `1.8`.


### Key Store

To use a key store which is compatible with this tool you can use following command:

    keytool -keystore thisIsMyKeyStore.ks -genkey -alias client -keyalg rsa

### Dependency Checker

The dependency checker is not bound to mavens verify phase. Run it explicitly using:

    ./mvnw org.owasp:dependency-check-maven:check

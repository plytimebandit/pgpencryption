# pgpencryption

This PGP encryption tool can be used to encrypt and decrypt files.

I tried to keep it simple.
Just build the jar by executing e.g. `mvn clean verify`
(the unit tests might take a while, so you might want to skip them)
and run the jar by executing `java -jar pgpencryption-1.0-SNAPSHOT-jar-with-dependencies.jar`.
This will show you the usage.

There are just three scenarios:

- create keys
- encrypt file
- decrypt file

That's it. Have fun.
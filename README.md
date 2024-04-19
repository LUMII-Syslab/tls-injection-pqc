# Integration of PQC algorithms into the BouncyCastle TLS Injection Mechanism (TLS-IM)

*by Sergejs Kozlovičs, 2024*

This repository complements our BouncyCastle TLS Injection Mechanism with the ability to use PQC signature algorithms for client and server authentication as well as PQC KEMs for key exchange.

## Before Use

First, clone the BC TLS-IM into some subdirectory of your project (e.g., into `src/tls-injection-mechanism`).

Add the following BC directories as source sets, e.g., (for Gradle):

```
sourceSets.main {
    java {
        srcDirs 'src/main/java',
                'src/tls-injection-mechanism/core/src/main/java',
                'src/tls-injection-mechanism/pkix/src/main/java',
                'src/tls-injection-mechanism/prov/src/main/java',
                'src/tls-injection-mechanism/tls/src/main/java',
                'src/tls-injection-mechanism/tls/src/main/jdk1.9/org/bouncycastle/jsse/provider',
                // ^^^ important that we do not include module-info.java (otherwise, the whole BC module farm is needed)
                // ^^^ and org/bouncycastle/tls/crypto/impl/jcajce/** (otherwise, there are duplicate class files)
                'src/tls-injection-mechanism/util/src/main/java'
                
                ...
    }
}
```

Second, clone this repository, e.g., into `src/tls-injection-pqc`. Then add the following directory to srcDirs:

```
                'src/tls-injection-pqc/src/main/java'
```

## Increasing TLS Handshake Message Size

First, you will need to instruct BouncyCastle and Java to increate the limit for the TLS handshake message due to the fact that PQC signatures are huge (and they are transmitted during the handshake).

```java
 System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));
```

## Using PQC Signature Algorithms

For a PQC signature algorithm, you just need to create an instance of it (implementing `SigAlgAPI`) and pass it to an instance of `InjectableAlgorithms` by invoking `withSigAlg`:

```
InjectableSphincsPlus mySphincs = new InjectableSphincsPlus();
InjectableAlgorithms algs = new InjectableAlgorithms()
                .withSigAlg(
                    "SPHINCS+-SHA2-128F", // algorithm name
                    List.of(new String[]{}), // no aliases
                    new ASN1ObjectIdentifier("1.3.9999.6.4").branch("13"), // OID
                    0xfeb3, // TLS code point for negotiating signatures
                    mySphincs // SigAlgAPI implementation
                );
```

> You can add multiple signature algorithms and KEMs by invoking withSigAlg and withKEM multiple times.

Finally, `push()` the injectable algorithms into the TLS `InjectionPoint`.

```
InjectionPoint.theInstance().push(algs);
```

## Using PQC KEMs

For a KEM, you need to provide a factory (a constructor is also OK) which is able to create KEM instances (implementing the KEM interface) on demand.

Pass this factory to an instance of `InjectableAlgorithms` by invoking `withKEM`:

```java
InjectableAlgorithms algs = new InjectableAlgorithms()
                .withKEM(
                    "FrodoKEM-640-AES", // algorithm name
                    0x0200, // TLS code point for negotiating a KEM
                    InjectableFrodoKEM::new, // the factory (=the constructor)
                    InjectableKEMs.Ordering.BEFORE // before or after existing KEMs
                );
```

> You can add multiple signature algorithms and KEMs by invoking withSigAlg and withKEM multiple times.

For KEMs, the ordering is important since it will be used in the KEM negotiation process. The first KEM will have a priority. Thus, we allow to specify KEM ordering using `InjectableKEMs.Ordering.BEFORE` or `InjectableKEMs.Ordering.AFTER`.

If you want to exclude the default KEMs (usually, ECC in TLSv1.3) from the negotiation process, use `withoutDefaultKEMs()`:

```java
algs = algs.withoutDefaultKEMs();
```

Finally, `push()` the injectable algorithms into the TLS `InjectionPoint`.

```
InjectionPoint.theInstance().push(algs);
```

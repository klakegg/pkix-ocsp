# OCSP Client

[![Build Status](https://travis-ci.org/klakegg/pkix-ocsp.svg?branch=master)](https://travis-ci.org/klakegg/pkix-ocsp)
[![Codecov](https://codecov.io/gh/klakegg/pkix-ocsp/branch/master/graph/badge.svg)](https://codecov.io/gh/klakegg/pkix-ocsp)


## Getting started

Include dependency in your pom.xml:

```xml
<dependency>
    <groupId>net.klakegg.pkix</groupId>
    <artifactId>pkix-ocsp</artifactId>
    <version>0.9.0</version>
</dependency>
```

Create your own validator:

```java
// Create OCSP Client using builder.
OcspClient client = OcspClient.builder()
        .set(OcspClient.EXCEPTION_ON_UNKNOWN, false) // Remove to trigger exception on 'UNKNOWN'.
        .set(OcspClient.EXCEPTION_ON_REVOKED, false) // Remove to trigger exception on 'REVOKED'.
        .build();

// Verify certificate (issuer certificate required).
CertificateResult response = client.verify(certificate, issuer);

// Prints 'GOOD', 'REVOKED' or 'UNKNOWN'.
System.out.println(response.getStatus());
```
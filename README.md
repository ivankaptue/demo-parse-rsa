## Simple Java program to convert String to RSAPrivateKey and RSAPublicKey

#### Usage

```java


RSAParser parser=new RSAParserImpl(KeyFactory.getInstance("RSA"));
        parser.parsePrivateKey("PRIVATE_KEY")
        parser.parsePublicKey("PUBLIC_KEY")
```

`parsePrivateKey()` and `parsePublicKey()` methods can throw `RSAParserException`when error occur during parsing.


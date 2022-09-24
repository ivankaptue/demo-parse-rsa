## Simple Java program to convert String to RSAPrivateKey and RSAPublicKey

#### Usage

```java
import com.klid.RSAParser;
import com.klid.RSAParserImpl;

import java.security.KeyFactory;

RSAParser parser=new RSAParserImpl(KeyFactory.getInstance("RSA"));
        parser.parsePrivateKey("PRIVATE_KEY")
        parser.parsePublicKey("PUBLIC_KEY")
```

`parsePrivateKey()` and `parsePublicKey()` methods can throw `RSAParserException`when error occur during parsing.


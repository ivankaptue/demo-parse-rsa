package com.klid;

import org.jetbrains.annotations.NotNull;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author Ivan Kaptue
 */
public class RSAParserImpl implements RSAParser {

    public static final String RSA = "RSA";
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    private KeyFactory keyFactory;

    public RSAParserImpl(KeyFactory keyFactory) {
        setKeyFactory(keyFactory);
    }

    public void setKeyFactory(KeyFactory keyFactory) {
        if (!RSA.equals(keyFactory.getAlgorithm())) {
            throw new RSAParserException("Algorithm must be RSA");
        }
        this.keyFactory = keyFactory;
    }

    @Override
    public RSAPrivateKey parsePrivateKey(@NotNull String privateKey) {
        try {
            var key = privateKey.replaceAll("\\n", "")
                    .replace(BEGIN_PRIVATE_KEY, "")
                    .replace(END_PRIVATE_KEY, "");
            var spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
            return (RSAPrivateKey) keyFactory.generatePrivate(spec);
        } catch (Exception ex) {
            throw new RSAParserException("Error when parsing private key", ex);
        }
    }

    @Override
    public RSAPublicKey parsePublicKey(@NotNull String publicKey) {
        try {
            var key = publicKey.replaceAll("\\n", "")
                    .replace(BEGIN_PUBLIC_KEY, "")
                    .replace(END_PUBLIC_KEY, "");
            var spec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception ex) {
            throw new RSAParserException("Error when parsing public key", ex);
        }
    }
}

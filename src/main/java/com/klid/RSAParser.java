package com.klid;

import org.jetbrains.annotations.NotNull;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Ivan Kaptue
 */
public interface RSAParser {

    RSAPrivateKey parsePrivateKey(@NotNull String privateKey) throws RSAParserException;

    RSAPublicKey parsePublicKey(@NotNull String publicKey) throws RSAParserException;
}

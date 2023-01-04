package com.klid.rsaloader;

import org.jetbrains.annotations.NotNull;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Ivan Kaptue
 */
public interface RSALoader {

    RSAPrivateKey parsePrivateKey(@NotNull String privateKey) throws RSALoaderException;

    RSAPublicKey parsePublicKey(@NotNull String publicKey) throws RSALoaderException;
}

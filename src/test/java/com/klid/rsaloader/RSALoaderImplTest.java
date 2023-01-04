package com.klid.rsaloader;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;

/**
 * @author Ivan Kaptue
 */
class RSALoaderImplTest {

    private static final String PRIVATE_KEY_FILE = "src/test/resources/private_key.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/public_key.pem";

    private RSALoader parser;

    @BeforeEach
    public void beforeEach() throws NoSuchAlgorithmException {
        parser = new RSALoaderImpl(KeyFactory.getInstance("RSA"));
    }

    @Test
    public void testParsePrivateKeyError() {
        assertThatThrownBy(() -> parser.parsePrivateKey(anyString()))
                .isInstanceOf(RSALoaderException.class)
                .hasMessage("Error when parsing private key");
    }

    @Test
    public void testParsePrivateKeySuccess() {
        var privateKey = parser.parsePrivateKey(loadKeyFromFile(PRIVATE_KEY_FILE));

        assertThat(privateKey).isNotNull();
    }

    @Test
    public void testParsePublicKeyError() {
        assertThatThrownBy(() -> parser.parsePublicKey(anyString()))
                .isInstanceOf(RSALoaderException.class)
                .hasMessage("Error when parsing public key");
    }

    @Test
    public void testParsePublicKeySuccess() {
        var privateKey = parser.parsePublicKey(loadKeyFromFile(PUBLIC_KEY_FILE));

        assertThat(privateKey).isNotNull();
    }

    @Test
    public void testSetKeyFactoryNotRSA() {
        assertThatThrownBy(() -> new RSALoaderImpl(KeyFactory.getInstance("DSA")))
                .isInstanceOf(RSALoaderException.class)
                .hasMessage("Algorithm must be RSA");
    }

    @Test
    public void testSetKeyFactoryRSA() {
        Assertions.assertDoesNotThrow(() -> new RSALoaderImpl(KeyFactory.getInstance("RSA")));
    }

    private String loadKeyFromFile(String filePath) {
        try {
            var file = new File(filePath);
            return Files.readAllLines(file.toPath()).stream()
                    .map(line -> line.concat("\n"))
                    .collect(Collectors.joining());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

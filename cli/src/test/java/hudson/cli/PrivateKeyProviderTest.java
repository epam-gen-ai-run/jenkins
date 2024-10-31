package hudson.cli;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
keys were generated with ssh-keygen from OpenSSH_7.9p1, LibreSSL 2.7.3
*/
@Execution(ExecutionMode.CONCURRENT)
class PrivateKeyProviderTest {

    @ParameterizedTest
    @MethodSource("provideKeys")
    void loadKey(String resourceName, String password, Class<? extends Exception> expectedException) {
        File file = new File(this.getClass().getResource(resourceName).getFile());
        if (expectedException == null) {
            assertKeyPairNotNull(file, password);
        } else {
            assertThrows(expectedException, () -> PrivateKeyProvider.loadKey(file, password));
        }
    }

    private static Stream<Arguments> provideKeys() {
        return Stream.of(
                Arguments.of("dsa", null, null),
                Arguments.of("dsa-password", "password", null),
                Arguments.of("rsa", null, null),
                Arguments.of("rsa-password", "password", null),
                Arguments.of("openssh", null, null),
                Arguments.of("openssh-pkcs8", "password", null),
                Arguments.of("openssh-rfc4716", "password", null),
                Arguments.of("openssh-multiple-keys", "password", InvalidKeySpecException.class),
                Arguments.of("blank", "password", InvalidKeyException.class),
                Arguments.of("openssh-broken", "password", IllegalArgumentException.class)
        );
    }

    /**
     * Asserts the keyPair private and public are not null.
     * @param file the file to load the key from
     * @param password the password
     */
    void assertKeyPairNotNull(File file, String password) {
        try {
            KeyPair keyPair = PrivateKeyProvider.loadKey(file, password);
            assertNotNull(keyPair);
            assertNotNull(keyPair.getPrivate());
            assertNotNull(keyPair.getPublic());
        } catch (IOException e) {
        } catch (GeneralSecurityException e) {
            // Handle the GeneralSecurityException
            e.printStackTrace();
        }
    }
}

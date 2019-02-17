package com.ptitficus.pgp.encryption;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

public class App {
    private final static String pubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQENBFxojVoBCADDOTZIeI7d7o4Xgg9MQn+Fw02RQYc/lpl2EGEhluQGdKWPf/8F\n" +
            "V2a8v1tOIDFkL/4+aA4bTEVidTP6LNEdIjPXmqdn3nqkPV6OQTU35W3RFefsQods\n" +
            "KZz31gPIeBzDoUJ5vStoGFusIf+WPwAc984BGtupwUdGFWBAmkvzpadBsNNoh6ON\n" +
            "ZLGJ8BG7nZF5sM3IFjcXeMnYJ+3HDtvgQ7hWgKIXwkbk5B8qX5FrQgYEQPSHj2Dr\n" +
            "zMYCcVa3r5Uh1Rcxo3lpGNtet9k2QyFdKjkg0dbKYHx9E9ZERk4oO15RtW/Hn4uJ\n" +
            "5D7Dk+4Y8VHk0tx3lUJLAc9crVVHQqpws3JZABEBAAG0IkJlbmphbWluIDxiZW5q\n" +
            "YW1pbi5jYXZ5QGdtYWlsLmNvbT6JAVQEEwEIAD4WIQR3lz5BOaouYQrRmhoa6crr\n" +
            "a3IyvwUCXGiNWgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRAa\n" +
            "6crra3Iyv0OqB/97CUqYWA/DFbq/X3XKbnWb+Ia0DHwemCKceNtqzf6oXaxgw4sp\n" +
            "9j4B+ykjuAUFFWCSZZZQpsNpxEmJWEFhLw/sagFCXgHmNZjPHPy9jr/D5SRIC5B0\n" +
            "DlgEobr6D77hbVMborOXUfSiEzHSOVMmBSgsfm4Kq9ruMhB2qfKIBkEJRruPZ08w\n" +
            "T+K0hKcEfkJNTNTXAZLGy+pT4RO2ahK3Lr6c8Vhr6CSui0b1999lZ2ootDCBnq5b\n" +
            "7RT2WeiaBNQRzowZ/H9vuatYhaAIQ8nwm+nq30ols9JApJKIW+V8Lgr8NEe38yki\n" +
            "PkFf5jCJb0rDgITvJH6IFeudgFwbjQx3ClnJuQENBFxojVoBCACs26N9cHBcHXEH\n" +
            "xI1MPLigv0EZ96Ti8EoT8dGzhRufvXbAx3UalUBVN99aMAO8B5V+23+Y+LigUuwd\n" +
            "gRos/uh7zMUVWuhXYOd9F/0qZp2Yfr3tJ67bAGxvqcB0iicN2vRDUxgnVbhX0GTy\n" +
            "u0mCd4jfXYifw+WjGLiM3tjj2lMP4p6Iw9wuQyXsh9PGbLr41OaWTHUuEsRGVx2M\n" +
            "O12pDEP1A0Ts1vZ/P2vWfOPzH00xRLg1mCqhSIcO0rBOIXOMpMO6Z9/0ThFSU0R5\n" +
            "jkoycXzdYZ/RIPZPpjvZEplM0AgFBZ7hrqvA1wrdphFziP92jI1zV0UChJuMDhxN\n" +
            "LU6JIy9JABEBAAGJATwEGAEIACYWIQR3lz5BOaouYQrRmhoa6crra3IyvwUCXGiN\n" +
            "WgIbDAUJA8JnAAAKCRAa6crra3Iyv7KxCACA0LRLmVkFdg211evHDbA3j6VNkerE\n" +
            "fgRFcYlg5M6bXVskw2mgCrMX2a1wY7MsTdwZClWhrAkholYcHDk7eECHUVxK/Ec9\n" +
            "C0Xuc7DYhWrAqYKjoRv5QCAo8lZQYXtRQlZJ6RqAfywZhfFKCnCV716oXvxNRFpR\n" +
            "cIrpoJUBSxsbThQ1e6naU+cMWTklgydZZmig9piuRj98wFQdLb9zWEGCNBw7tpnk\n" +
            "vaFRnp3o7zSu/dTJjY0jwHOXBosRiF7NlOg4cfU36Uy/v3QzjOWWyREsIGFXU+GY\n" +
            "r8FeFsVqEwfsDIbnuSDNaEbZJmTzO+U2xBxSYT0d96QK1sIshmLrc8mM\n" +
            "=6m7H\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    public static void main(String[] args) throws IOException, PGPException, NoSuchProviderException, SignatureException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        final String original_message = "GPG using bouncy castle is hard";

        KeyringConfig keyringConfigOfSender = keyringConfigInMemoryForKeys(pubKey);

        ByteArrayOutputStream result = new ByteArrayOutputStream();

        try (
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384 * 1024);

                final OutputStream outputStream = BouncyGPG
                        .encryptToStream()
                        .withConfig(keyringConfigOfSender)
                        .withStrongAlgorithms()
                        .toRecipient("benjamin.cavy@gmail.com")
                        .andDoNotSign()
                        .binaryOutput()
                        .andWriteTo(bufferedOutputStream);
                final ByteArrayInputStream is = new ByteArrayInputStream(original_message.getBytes())
        ) {
            Streams.pipeAll(is, outputStream);
        }

        result.close();
        byte[] chipertext = result.toByteArray();

        try (FileOutputStream fos = new FileOutputStream("doc")) {
            fos.write(chipertext);
        }
    }

    public static KeyringConfig keyringConfigInMemoryForKeys(final String exportedPubKey) throws IOException, PGPException {
        final InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());

        keyring.addPublicKey(exportedPubKey.getBytes(StandardCharsets.US_ASCII));
        return keyring;
    }

}

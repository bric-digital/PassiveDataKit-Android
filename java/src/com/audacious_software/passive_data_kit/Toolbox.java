package com.audacious_software.passive_data_kit;

import android.util.Base64;

import com.goterl.lazysodium.SodiumAndroid;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

public class Toolbox {
    private static final Pattern NONLATIN = Pattern.compile("[^\\w-]");
    private static final Pattern WHITESPACE = Pattern.compile("[\\s]");
    private static final Pattern EDGESDHASHES = Pattern.compile("(^-|-$)");
    private static final int SODIUM_CRYPTO_BOX_MACBYTES = 16;
    private static final int SODIUM_CRYPTO_BOX_NONCEBYTES = 24;
    private static final int SODIUM_CRYPTO_HASH_SHA512_BYTES = 64;

    public static String toSlug(String input) {
        String nowhitespace = WHITESPACE.matcher(input).replaceAll("-");
        String normalized = Normalizer.normalize(nowhitespace, Normalizer.Form.NFD);
        String slug = NONLATIN.matcher(normalized).replaceAll("");
        slug = EDGESDHASHES.matcher(slug).replaceAll("");

        return slug.toLowerCase(Locale.ENGLISH);
    }

    public static byte[] decodeBase64(String encoded) {
        return Base64.decode(encoded, Base64.DEFAULT);
    }

    public static String encodeBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.CRLF);
    }

    public static String encrypt(byte[] privateKey, byte[] publicKey, byte[] nonce, String payload) {
        SodiumAndroid sodium = new SodiumAndroid();

        byte[] message = payload.getBytes(StandardCharsets.UTF_8);

        long ciphertextLength = Toolbox.SODIUM_CRYPTO_BOX_MACBYTES + message.length;

        byte[] ciphertext = new byte[(int) ciphertextLength];

        if (sodium.crypto_box_easy(ciphertext, message, message.length, nonce, publicKey, privateKey) == 0) {
            return Toolbox.encodeBase64(ciphertext);
        }

        return payload;
    }

    public static String hash(String payload) {
        SodiumAndroid sodium = new SodiumAndroid();

        byte[] message = payload.getBytes(StandardCharsets.UTF_8);

        byte[] hashText = new byte[(int) Toolbox.SODIUM_CRYPTO_HASH_SHA512_BYTES];

        sodium.crypto_hash_sha512(hashText, message, message.length);

        return Toolbox.encodeBase64(hashText);
    }

    public static byte[] randomNonce() {
        SodiumAndroid sodium = new SodiumAndroid();

        long nonceLength = Toolbox.SODIUM_CRYPTO_BOX_NONCEBYTES;

        byte[] nonce = new byte[(int) nonceLength];

        sodium.randombytes_buf(nonce,(int) nonceLength);

        return nonce;
    }
}
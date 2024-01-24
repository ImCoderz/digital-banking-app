package org.sid.ebankingbackend.Security;



import java.security.SecureRandom;
        import java.util.Base64;

public class SecretKeyGenerator {

    public static void main(String[] args) {
        // Generate a random byte array as the secret key
        byte[] secretKeyBytes = generateRandomBytes(256);

        // Convert the byte array to a Base64-encoded string
        String secretKey = base64Encode(secretKeyBytes);

        System.out.println("Generated Secret Key: " + secretKey);
    }

    private static byte[] generateRandomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    private static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}

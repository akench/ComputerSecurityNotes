/*
 *               Cryptr
 *
 * Cryptr is a java encryption toolset
 * that can be used to encrypt/decrypt files
 * and keys locally, allowing for files to be
 * shared securely over the world wide web
 *
 * Cryptr provides the following functions:
 *	 1. Generating a secret key
 *   2. Encrypting a file with a secret key
 *   3. Decrypting a file with a secret key
 *   4. Encrypting a secret key with a public key
 *   5. Decrypting a secret key with a private key
 *
 */

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.*;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.*;

public class Cryptr {

    /**
     * Generates an 128-bit AES secret key and writes it to a file Used to encrypt
     * the file with symmetric algorithm
     *
     * @param secKeyFile name of file to store secret key
     */
    static void generateKey(String secKeyFile) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGen.generateKey();

        try (FileOutputStream out = new FileOutputStream(secKeyFile)) {
            byte[] keyBytes = secretKey.getEncoded();
            out.write(keyBytes);
        }
    }

    private static Cipher createCipherAES(String secKeyFile, int mode, IvParameterSpec ivParameterSpec)
            throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(secKeyFile));
        SecretKeySpec skey = new SecretKeySpec(keyBytes, "AES");

        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(mode, skey, ivParameterSpec);

        return ci;
    }

    private static Cipher createCipherRSA(String secKeyFile, int mode) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(secKeyFile));
        EncodedKeySpec ks = (mode == Cipher.ENCRYPT_MODE) 
                                ? new X509EncodedKeySpec(keyBytes) 
                                : new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        // if encrypting, generate the public key
        Key key = (mode == Cipher.ENCRYPT_MODE) 
                    ? kf.generatePublic(ks) 
                    : kf.generatePrivate(ks);

        Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        ci.init(mode, key);
        return ci;
    }

    private static IvParameterSpec createIvParamSpec() {
        // Need a random byte generator to construct the
        // initialization vector for AES-CBC
        SecureRandom srandom = new SecureRandom();

        // Construct the initialization vector
        byte[] initializationVector = new byte[128 / 8];
        srandom.nextBytes(initializationVector);
        return new IvParameterSpec(initializationVector);
    }

    private static void processFile(Cipher ci, FileInputStream in, FileOutputStream out) throws Exception {
        // Now encrypt the contents of the original file
        // TODO: try with diff buff size
        byte[] inputBuf = new byte[1024];
        int len;
        while ((len = in.read(inputBuf)) != -1) {
            byte[] outputBuf = ci.update(inputBuf, 0, len);

            if (outputBuf != null) {
                out.write(outputBuf);
            }
        }

        byte[] outputBuf = ci.doFinal();

        if (outputBuf != null) {
            out.write(outputBuf);
        }
    }

    /**
     * Extracts secret key from a file, generates an initialization vector, uses
     * them to encrypt the original file, and writes an encrypted file containing
     * the initialization vector followed by the encrypted file data
     *
     * @param originalFile  name of file to encrypt
     * @param secKeyFile    name of file storing secret key
     * @param encryptedFile name of file to write iv and encrypted file data
     */
    static void encryptFile(String originalFile, String secKeyFile, String encryptedFile) throws Exception {

        IvParameterSpec ivParamSpec = createIvParamSpec();
        Cipher ci = createCipherAES(secKeyFile, Cipher.ENCRYPT_MODE, ivParamSpec);

        try (FileInputStream in = new FileInputStream(originalFile);
                FileOutputStream out = new FileOutputStream(encryptedFile)) {
            // write the Init Vector to the beginning of the encrypted file
            // so that it can be used when decrypting
            out.write(ivParamSpec.getIV());

            // Now dump the encrypted contents to the output file
            processFile(ci, in, out);
        }
    }

    /**
     * Extracts the secret key from a file, extracts the initialization vector from
     * the beginning of the encrypted file, uses both secret key and initialization
     * vector to decrypt the encrypted file data, and writes it to an output file
     *
     * @param encryptedFile name of file storing iv and encrypted data
     * @param secKeyFile    name of file storing secret key
     * @param outputFile    name of file to write decrypted data to
     */
    static void decryptFile(String encryptedFile, String secKeyFile, String outputFile) throws Exception {

        try (FileInputStream in = new FileInputStream(encryptedFile);
                FileOutputStream out = new FileOutputStream(outputFile)) {

            // Construct the cipher object using the initialization
            // vector, which is the first 16 bytes of the file.
            byte[] iv = new byte[128 / 8];
            in.read(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher ci = createCipherAES(secKeyFile, Cipher.DECRYPT_MODE, ivParameterSpec);

            // Decrypt the input stream (encrypted file) and
            // write to the outputFile using the specified Cipher.
            processFile(ci, in, out);
        }

    }

    /**
     * Extracts secret key from a file, encrypts a secret key file using a public
     * Key (*.der) and writes the encrypted secret key to a file
     *
     * @param secKeyFile name of file holding secret key
     * @param pubKeyFile name of public key file for encryption
     * @param encKeyFile name of file to write encrypted secret key
     */
    static void encryptKey(String secKeyFile, String pubKeyFile, String encKeyFile) throws Exception {

        Cipher ci = createCipherRSA(pubKeyFile, Cipher.ENCRYPT_MODE);

        try (FileInputStream in = new FileInputStream(secKeyFile);
                FileOutputStream out = new FileOutputStream(encKeyFile)) {
            processFile(ci, in, out);
        }

    }

    /**
     * Decrypts an encrypted secret key file using a private Key (*.der) and writes
     * the decrypted secret key to a file
     *
     * @param encKeyFile  name of file storing encrypted secret key
     * @param privKeyFile name of private key file for decryption
     * @param secKeyFile  name of file to write decrypted secret key
     */
    static void decryptKey(String encKeyFile, String privKeyFile, String secKeyFile) throws Exception {

        Cipher ci = createCipherRSA(privKeyFile, Cipher.DECRYPT_MODE);

        try (FileInputStream in = new FileInputStream(encKeyFile);
                FileOutputStream out = new FileOutputStream(secKeyFile)) {
            processFile(ci, in, out);
        }

    }

    /**
     * Main Program Runner
     */
    public static void main(String[] args) throws Exception {

        String func;

        if (args.length < 1) {
            func = "";
        } else {
            func = args[0];
        }

        switch (func) {
        case "generatekey":
            if (args.length != 2) {
                System.out.println("Invalid Arguments.");
                System.out.println("Usage: Cryptr generatekey <key output file>");
                break;
            }
            System.out.println("Generating secret key and writing it to " + args[1]);
            generateKey(args[1]);
            break;
        case "encryptfile":
            if (args.length != 4) {
                System.out.println("Invalid Arguments.");
                System.out.println(
                        "Usage: Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
                break;
            }
            System.out.println("Encrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
            encryptFile(args[1], args[2], args[3]);
            break;
        case "decryptfile":
            if (args.length != 4) {
                System.out.println("Invalid Arguments.");
                System.out.println(
                        "Usage: Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
                break;
            }
            System.out.println("Decrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
            decryptFile(args[1], args[2], args[3]);
            break;
        case "encryptkey":
            if (args.length != 4) {
                System.out.println("Invalid Arguments.");
                System.out.println(
                        "Usage: Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>");
                break;
            }
            System.out
                    .println("Encrypting key file " + args[1] + " with public key file " + args[2] + " to " + args[3]);
            encryptKey(args[1], args[2], args[3]);
            break;
        case "decryptkey":
            if (args.length != 4) {
                System.out.println("Invalid Arguments.");
                System.out.println(
                        "Usage: Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
                break;
            }
            System.out
                    .println("Decrypting key file " + args[1] + " with private key file " + args[2] + " to " + args[3]);
            decryptKey(args[1], args[2], args[3]);
            break;
        default:
            System.out.println("Invalid Arguments.");
            System.out.println("Usage:");
            System.out.println("  Cryptr generatekey <key output file>");
            System.out.println("  Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
            System.out.println("  Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
            System.out
                    .println("  Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file> ");
            System.out
                    .println("  Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
        }

        System.exit(0);

    }

}
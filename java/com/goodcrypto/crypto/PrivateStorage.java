package com.goodcrypto.crypto;

import java.util.Random;

import com.goodcrypto.crypto.key.KeyService;
import com.goodcrypto.crypto.key.KeyServiceFactory;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.io.NullLog;

import org.bouncycastle.util.encoders.Base64;

/**
 * Encryption and decryption of private storage.
 * <p>
 * This class encrypts storage, not messages.
 * Storage encryption is from a key id to the same key id.
 * Message encryption is from the sender's key id to the recipient's key id.
 * <p>
 * Uses the default crypto and key service.
 *
 * <p>Copyright 2005-2006 GoodCrypto
 * <br>Last modified: 2007.04.19
 *
 * @author     GoodCrypto
 * @version    0.1
 */

public class PrivateStorage
implements Constants
{
    // we usually don't keep a log, since this class encrypts passphrases
    private final static boolean Logging = false;
    private static Log log;

    private static Random random = com.goodcrypto.util.Random.getDefaultRandom();

    private String keyID;
    private String passphrase;
    private KeyService crypto;

    static {
        if (Logging) {
            log = new LogFile();
        }
        else {
            log = new NullLog();
        }
    }


    /**
     *  PrivateStorage constructor.
     *
     * @param  keyID       key identifier
     * @param  passphrase  passphrase
     */
    public PrivateStorage(String keyID, String passphrase)
    {
        log.println("setting keyID: " + keyID);
        this.keyID = keyID;
        
        if (LogPassphrases) {
            log.println("DEBUG: setting passphrase: " + passphrase);
        }
        this.passphrase = passphrase;
    }


    /**
     * Create a random passphrase.
     * The quality of the passphrase depends on the quality of the jvm's Random().
     *
     * @return    passphrase
     */
    public static String createPassphrase()
    {
        final int ByteCount = 100;
        return createPassphrase(ByteCount);
    }


    /**
     * Create a random passphrase.
     * The quality of the passphrase depends on the quality of the jvm's Random().
     *
     * @param  byteCount  number of random bytes encoded in passphrase
     * @return            passphrase
     */
    public static String createPassphrase(int byteCount)
    {
        byte[] bytes = new byte[byteCount];
        random.nextBytes(bytes);

        String passphrase = PrivateStorage.toString(bytes);

        // trim trailing "=" from base64 encoded string
        while (passphrase.endsWith("=")) {
            passphrase = passphrase.substring(0, passphrase.length() - 1);
        }

        // log.println("Created passphrase: " + passphrase);

        return passphrase;
    }


    /**
     *  Encode a byte array as a String.
     *  For all ascii-armored pgp packet streams, the encoded
     *  begining and ending will be the same, since you are always encoding
     *  "-----BEGIN PGP MESSAGE-----" and "-----END PGP MESSAGE-----".
     *
     * @param  data  bytes
     * @return       encoded string
     */
    public static String toString(byte[] data)
    {
        log.println("before Base64 encoding: " + new String(data));
        String base64Encoded = new String(Base64.encode(data));
        log.println("after Base64 encoding:\n" + base64Encoded);
        return base64Encoded;
    }


    /**
     *  Decode an encoded String back to a byte array.
     *
     * @param  data  encoded string
     * @return       bytes
     */
    public static byte[] toBytes(String data)
    {
        log.println("before Base64 decoding:\n" + data);
        byte [] base64Decoded = Base64.decode(data.getBytes());
        log.println("after Base64 decoding:\n" + new String(base64Decoded));
        return base64Decoded;
    }


    /**
     * Create a new key.
     * The key is added to the keyring.
     *
     * @param  keyID                key identifier
     * @throws  CryptoException     if there is no passphrase
     */
    public void createKey(String keyID)
        throws CryptoException
    {
        verifyHavePassphrase();
        getKeyService().create(keyID, getPassphrase());
    }


    /**
     *  Sets the crypto.
     *  This must be a KeyService, not just a CryptoService.
     *
     * @param  crypto  new crypto
     */
    public void setCrypto(KeyService crypto)
    {
        log.println("setting key service: " + crypto.getClass().getName());
        this.crypto = crypto;
    }


    /**
     *  Gets the crypto service.
     *
     * @return                   crypto service
     * @throws  CryptoException  crypto exception
     */
    public CryptoService getCrypto()
        throws CryptoException
    {
        return (CryptoService) getKeyService();
    }


    /**
     *  Gets the crypto service as a KeyService.
     *
     * @return                   crypto service
     * @throws  CryptoException  crypto exception
     */
    public KeyService getKeyService()
        throws CryptoException
    {
        if (crypto == null) {
            crypto = (KeyService) KeyServiceFactory.getDefaultService();
            log.println(
                "using default key service: " + 
                crypto.getClass().getName());
        }
        return crypto;
    }


    /**
     *  Sets the key ID.
     *
     * @param  keyID  new key ID
     */
    public void setKeyID(String keyID)
    {
        log.println("setting keyID: " + keyID);
        this.keyID = keyID;
    }


    /**
     *  Gets the key ID.
     *
     * @return    key ID
     */
    public String getKeyID()
    {
        return keyID;
    }


    /**
     *  Sets the passphrase.
     *
     * @param  passphrase  new passphrase
     */
    public void setPassphrase(String passphrase)
    {
        if (LogPassphrases) {
            log.println("DEBUG: setting passphrase: " + passphrase);
        }
        this.passphrase = passphrase;
    }


    /**
     *  Gets the passphrase.
     *
     * @return    passphrase
     */
    public String getPassphrase()
    {
        return passphrase;
    }


    /**
     *  Encrypt private data.
     *
     * @param  plaintext            Data to encrypt
     * @return                      Encrypted data
     * @throws  CryptoException     if there is no passphrase
     */
    public byte[] encrypt(byte[] plaintext)
        throws CryptoException
    {
        verifyHavePassphrase();
        log.println("before encryption:\n" + new String(plaintext));
        // because of a bc decrypt bug that prefixes garbage, we have to armor
        byte [] encryptedData = getCrypto().signEncryptAndArmor(
            plaintext, getKeyID(), getKeyID(), getPassphrase());
        log.println("after encryption:\n" + new String(encryptedData));
        return encryptedData;
    }


    /**
     *  Decrypt private data.
     *
     * @param  ciphertext           Data to decrypt
     * @return                      Decrypted data
     * @throws  CryptoException     if there is no passphrase
     */
    public byte[] decrypt(byte[] ciphertext)
        throws CryptoException
    {
        verifyHavePassphrase();
        log.println("before decryption:\n" + new String(ciphertext));
        byte [] plaintext = getCrypto().decrypt(ciphertext, getPassphrase());
        log.println("after decryption:\n" + new String(plaintext));
        return plaintext;
    }
    
    private void verifyHavePassphrase()
        throws CryptoException
    {
        if (getPassphrase() == null) {
            throw new CryptoException("Missing passphrase");
        }
    }

}


package com.goodcrypto.crypto;

/**
 * Cryptographic service provided by the Open Crypto Engine.
 * <p>
 * To avoid race conditions operations are atomic.
 * <p>
 * We would prefer to set the passphrase once because
 * different service providers need it at different times, and
 * because sending it more often than needed would be
 * a security risk. But since there is generally
 * only one active instance of each OCE service, then
 * one process' encrypt() could end up using another
 * process' passphrase.
 * <p>
 * We don't have a way to tell callers who signed something.
 * We can verify whether a known sender signed.
 *
 * <p>Copyright 2002-2005 GoodCrypto
 * <br>Last modified: 2005.03.07
 */
public interface CryptoService
{
    /**
     * Get the service provider's name.
     * @exception CryptoException crypto exception
     * @return name of the service provider
     */
    public String getName()
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Get the OCE plugin version.
     * @exception CryptoException crypto exception
     * @return plugin version
     */
    public String getPluginVersion()
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Get the version of the underlying crypto service provider.
     * @exception CryptoException crypto exception
     * @return Crypto version
     */
    public String getCryptoVersion()
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Determine if the crypto app is installed.
     *
     * How do we specify "static" in OpenCryptoEngine.idl?
     *
     * @return                      true if backend app is installed.
     */
    public boolean isAvailable();
    
    /**
     * Sign data with the secret key indicated by fromUserID, then encrypt with
     * the public key indicated by toUserID.
     * 
     * To avoid a security bug in OpenPGP we must sign before encrypting.
     * @exception CryptoException crypto exception
     * @param data Data to encrypt
     * @param fromUserID ID indicating which secret key to use. This is typically your own email address.
     * @param toUserID ID indicating which public key to use. This is typically an email address.
     * @param passphrase Passphrase
     * @return Encrypted data
     */
    public byte[] signAndEncrypt(byte[] data, String fromUserID, String toUserID, String passphrase)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Sign data with the secret key indicated by fromUserID, then encrypt with
     * the public key indicated by toUserID, then ASCII armor.
     * 
     * To avoid a security bug in OpenPGP we must sign before encrypting.
     * @exception CryptoException crypto exception
     * @param data Data to encrypt
     * @param fromUserID ID indicating which secret key to use. This is typically your own email address.
     * @param toUserID ID indicating which public key to use. This is typically an email address.
     * @param passphrase Passphrase
     * @return Encrypted data
     */
    public byte[] signEncryptAndArmor(byte[] data, String fromUserID, String toUserID, String passphrase)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Encrypt data with the public key indicated by toUserID.
     * @return Encrypted data
     * @param data Data to encrypt
     * @param toUserID ID indicating which public key to use. This is typically an email address.
     * @exception CryptoException crypto exception
     */
    public byte[] encryptOnly(byte[] data, String toUserID)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Decrypt data.
     * @exception CryptoException crypto exception
     * @param data Data to decrypt
     * @param passphrase Passphrase
     * @return Decrypted data
     */
    public byte[] decrypt(byte[] data, String passphrase)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Sign data with the private key indicated by userID.
     * @exception CryptoException crypto exception
     * @param data Data to sign
     * @param userID ID indicating which private key to use. This is typically an email address.
     * @param passphrase Passphrase
     * @return Signed data
     */
    public byte[] sign(byte[] data, String userID, String passphrase)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Verify data was signed by userID.
     * @return Whether data was signed by this user ID
     * @param userID user ID
     * @param data Data to verify
     * @exception CryptoException crypto exception
     */
    public boolean verify(byte[] data, String userID)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Get signer of data.
     * @exception CryptoException crypto exception
     * @param data Signed data
     * @return ID of the apparent signer, or null if none.
     */
    public String getSigner(byte[] data)
        throws com.goodcrypto.crypto.CryptoException;

    /**
     * Get list of user IDs.
     * 
     * Some crypto engines require an exact match to an existing user ID, no matter
     * what their docs say.
     * @exception CryptoException crypto exception
     * @return List of user IDs
     */
    public String[] getUserIDs()
        throws com.goodcrypto.crypto.CryptoException;

}

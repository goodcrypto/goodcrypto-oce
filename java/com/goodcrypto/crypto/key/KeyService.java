package com.goodcrypto.crypto.key;

/**
 *  Key interface for the Open Crypto Engine.
 *
 *  This interface is not yet generated from IDL, and so does not have a CORBA interface.
 *
 *  <p>Copyright 2004 GoodCrypto
 *  <br>Last modified: 2005.1.2
 */
public interface KeyService
{
    /**
     * Get the plugin's name.
     *
     * @return                                              Name of the plugin
     * @exception  CryptoException  crypto exception 
     */
    public String getName()
        throws com.goodcrypto.crypto.CryptoException;


    /**
     * Get the version of this plugin's implementation, i.e. the CORBA servant's version.
     *
     * @return                                              Plugin version
     * @exception  CryptoException  crypto exception 
     */
    public String getPluginVersion()
        throws com.goodcrypto.crypto.CryptoException;


    /**
     * Get the version of the underlying crypto.
     *
     * @return                                              Crypto version
     * @exception  CryptoException  crypto exception 
     */
    public String getCryptoVersion()
        throws com.goodcrypto.crypto.CryptoException;


    /**
     * Returns whether the specified function is supported.
     *
     * @param  func  The function to check
     * @return       Whether the function is supported
     */
    public boolean isFunctionSupported(String func);


    /**
     *          Create a new public key pair.
     *
     *  Create a new key and add it to the keyring.
     *
     * @param  userID                                       ID for the new key. This is typically an email address.
     * @param  passphrase                                   Passphrase
     * @exception  CryptoException  crypto exception 
     */
    public void create(String userID, String passphrase)
        throws com.goodcrypto.crypto.CryptoException;


    /**
     *          Delete a key.
     *
     *  Delete an existing key, or key pair, from the keyring.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @exception  CryptoException  crypto exception 
     */
    public void delete(String userID)
        throws com.goodcrypto.crypto.CryptoException;


    /**
     *          Import a public key.
     *
     *  Add a public key to the keyring.
     *
     * @param  data                                         Public key data.
     * @exception  CryptoException  crypto exception 
     */
    public void importPublic(byte[] data)
        throws com.goodcrypto.crypto.CryptoException;


    /**
     *          Export a public key.
     *
     *  Export a public key from the keyring.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Public key
     * @exception  CryptoException  crypto exception 
     */
    public String exportPublic(String userID)
        throws com.goodcrypto.crypto.CryptoException;


    /**
     *          Whether a key ID is valid.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Whether the key ID is valid
     * @exception  CryptoException  crypto exception 
     */
    public boolean isValid(String userID)
        throws com.goodcrypto.crypto.CryptoException;
       
    /**
     *          Returns a key's fingerprint.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Fingerprint
     * @exception  CryptoException  crypto exception 
     */ 
    public String getFingerprint(String userID)
        throws com.goodcrypto.crypto.CryptoException;
}


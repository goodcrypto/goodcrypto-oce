package com.goodcrypto.crypto.key;

import java.io.IOException;
import java.security.Security;

import com.goodcrypto.crypto.CryptoException;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Bouncy Castle crypto key plugin.
 *
 * Most of the work is deferred to OpenPGP and its superclass OpenPGPKeys,
 * which actually uses Bouncy Castle.
 *
 * <p>Copyright 2004 GoodCrypto
 * <br>Last modified: 2007.04.07
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class BCPlugin
     extends com.goodcrypto.crypto.BCPlugin
     implements KeyService, BCPluginConstants
{
    private static Log log = new LogFile();


    /** Creates a new BCPlugin object. */
    public BCPlugin()
    {
        Security.addProvider(new BouncyCastleProvider());
        log.println("Ready");
    }


    /**
     * Just for testing.
     *
     * @param  args  Command line arguments.
     */
    public static void main(String args[])
    {
        BCPlugin plugin = new BCPlugin();
        try {
            BCPlugin.log.println("deleting all user ids");
            String[] strings = plugin.getUserIDs();
            BCPlugin.log.println("" + strings.length + " user ids");
            for (int i = 0; i < strings.length; ++i) {
                BCPlugin.log.println("    " + (i + 1) + ": " + strings[i]);
                plugin.delete(strings[i]);
            }

            BCPlugin.log.println("Adding Test");
            plugin.create(com.goodcrypto.crypto.test.Constants.TestUser,
                com.goodcrypto.crypto.test.Constants.TestPassphrase);

            BCPlugin.log.println("Adding Test2");
            plugin.create(com.goodcrypto.crypto.test.Constants.TestUser2,
                com.goodcrypto.crypto.test.Constants.TestPassphrase2);

            String[] dumpArgs = {plugin.openpgp.getPublicKeyringPathname()}; //DEBUG
            try {
                org.bouncycastle.openpgp.examples.PubringDump.main(dumpArgs); //DEBUG
            }
            catch (Exception e) {
                log.print(e);
            }

            BCPlugin.log.println("Deleting Test");
            plugin.delete(com.goodcrypto.crypto.test.Constants.TestUser);

            /*
            plugin.log.println("Adding Test again");
            plugin.create(com.goodcrypto.crypto.test.Constants.TestUser,
                com.goodcrypto.crypto.test.Constants.TestPassphrase);
            */
        }
        catch (CryptoException ce) {
            BCPlugin.log.println("exception");
            BCPlugin.log.print(ce);
            System.err.print(ce);
        }
    }


    /**
     * Get the plugin's name.
     * (copied from KeyService)
     *
     * <p>
     * Ignore pmd - this already uses block level synchronization.
     *
     * @return    Name of the plugin
     */
    public synchronized String getName()
    {
        return BCPluginConstants.Name;
    }


    /**
     * Get the version of this plugin's implementation, i.e. the CORBA servant's version.
     * (copied from KeyService)
     *
     * <p>
     * Ignore pmd - this already uses block level synchronization.
     *
     * @return    Plugin version
     */
    public synchronized String getPluginVersion()
    {
        return "0.1";
    }


    /**
     * Returns whether the specified function is supported.
     *
     * @param  func  The function to check
     * @return       Whether the function is supported
     */
    public boolean isFunctionSupported(String func)
    {
        // this plugin supports all functions
        log.println("plugin " + getName() + " supports the function " + func);
        return true;
    }


    /**
     *          Whether a key ID is valid.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Whether the key ID is valid
     * @exception  CryptoException  crypto exception
     */
    public boolean isValid(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        try {
            return openpgp.getPublicEncryptionKey(userID) != null;
        }
        catch (Exception e) {
            log.print(e);
            throw new CryptoException(e.toString());
        }
    }


    /**
     *          Returns a key's fingerprint.
     *
     * @param  userID               ID for the key. This is typically an email address.
     * @return                      Fingerprint
     * @exception  CryptoException  crypto exception 
     */
    public String getFingerprint(String userID)
        throws CryptoException
    {
        return openpgp.getFingerprint(userID);
    }


    /**
     *          Create a new public key pair.
     *
     *  Create a new key and add it to the keyring.
     * (copied from KeyService)
     *
     * @param  userID                                       ID for the new key. This is typically an email address.
     * @param  passphrase                                   Passphrase
     * @exception  CryptoException  crypto exception 
     */
    public void create(String userID, String passphrase)
        throws com.goodcrypto.crypto.CryptoException
    {
        try {
            if (isValid(userID)) {
                String message = "key already exists: " + userID;
                log.println(message);
                throw new CryptoException(message);
            }
            else {
                openpgp.create(userID, passphrase);
            }
        }
        catch (CryptoException ce) {
            handleCryptoException(ce);
        }
    }


    /**
     *          Delete a key.
     *
     *  Delete an existing key, or key pair, from the keyring.
     * (copied from KeyService)
     *
     * @param  userID                                       ID for the new key. This is typically an email address.
     * @exception  CryptoException  crypto exception 
     */
    public void delete(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        try {
            openpgp.delete(userID);
        }
        catch (CryptoException ce) {
            handleCryptoException(ce);
        }
    }


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
        throws com.goodcrypto.crypto.CryptoException
    {
        String publicKey = null;

        try {
            publicKey = openpgp.exportPublic(userID);
        }
        catch (CryptoException ce) {
            handleCryptoException(ce);
        }

        return publicKey;
    }


    /**
     *          Import a public key.
     *
     *  Add a public key to the keyring.
     *  <p>
     *  Some crypto engines will allow more than one public key to be imported at
     *  one time, but applications should not rely on this.
     *
     * @param  data                                         Public key data.
     * @exception  CryptoException  crypto exception 
     */
    public void importPublic(byte[] data)
        throws CryptoException
    {
        try {
            openpgp.importPublic(data);
        }
        catch (CryptoException ce) {
            handleUnexpectedException(ce);
        }
    }


    /**
     *  Description of the Method.
     *
     * @param  ce                   Description of Parameter
     * @exception  CryptoException  crypto exception 
     */
    protected void handleCryptoException(CryptoException ce)
        throws CryptoException
    {
        log.print(ce);
        throw ce;
    }

}


package com.goodcrypto.crypto.key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import javax.mail.internet.InternetAddress;

import com.goodcrypto.crypto.BCConstants;
import com.goodcrypto.crypto.CryptoException;
import com.goodcrypto.crypto.CryptoService;
import com.goodcrypto.crypto.GPGConstants;
import com.goodcrypto.crypto.GPGPlugin;
import com.goodcrypto.crypto.OpenPGP;
import com.goodcrypto.crypto.PGPConstants;
import com.goodcrypto.crypto.PGPPlugin;
import com.goodcrypto.io.IgnoredLog;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.util.Subprogram;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * OpenPGP key utilities.
 *
 * We specify the packages in "implements"so we don't get the
 * current packages' interfaces by the same name.
 * Apparently "import" isn't effective in "implements".
 *
 * <p>Copyright 2004-2007 GoodCrypto
 * <br>Last modified: 2007.04.19
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class OpenPGPKeys
     implements KeyService,
    BCConstants, GPGConstants, PGPConstants, com.goodcrypto.crypto.Constants
{
    private final static String Version = "0.1";

    private final static String DSAProvider = "DSA";
    private final static String ElGamalProvider = "ElGamal";

    /** Empty String array used to specify the array type for Vector.toArray(). */
    private final static String[] EmptyStringArray = {};

    /** Logging keyrings currently results in infinite recursion. */
    private final static boolean LogKeyrings = false;

    private final static SecureRandom secureRandom = new SecureRandom();

    private static Log log = new LogFile();

    private OpenPGP openpgp;

    private String publicKeyringPathname = null;
    private String secretKeyringPathname = null;
    private PGPPublicKeyRingCollection publicKeyrings = null;
    private PGPSecretKeyRingCollection secretKeyrings = null;
    private boolean publicKeyringsNeedRefresh = true;
    private boolean secretKeyringsNeedRefresh = true;


    /** Constructor for OpenPGPKeys. */
    public OpenPGPKeys()
    {
        setDefaultKeyringPathnames();
    }


    /**
     * Constructor for OpenPGPKeys using keyring files for the specified plugin.
     *
     * @param  crypto  crypto service
     */
    public OpenPGPKeys(CryptoService crypto)
    {
        this();
        setKeyringPathnames(crypto);
    }


    /**
     * Constructor for OpenPGPKeys.
     *
     * @param  publicKeyringPathname  public keyring filename
     * @param  secretKeyringPathname  secret keyring filename
     */
    public OpenPGPKeys(String publicKeyringPathname, String secretKeyringPathname)
    {
        this();
        setPublicKeyringPathname(publicKeyringPathname);
        setSecretKeyringPathname(secretKeyringPathname);
    }


    /**
     *  Sets the log.
     *
     * @param  log  new log
     */
    public static void setLog(Log log)
    {
        OpenPGPKeys.log = log;
    }


    /**
     *  If a user ID includes spaces or "<" or ">", and is not quoted,
     *  surround it with quotes.
     *
     * @param  arg  command line arg
     * @return      quoted command line arg
     */
    public static String quoteUserID(String arg)
    {
        String quotedArg;

        if (arg.indexOf(' ') < 0 &&
            arg.indexOf('<') < 0 &&
            arg.indexOf('>') < 0) {

            quotedArg = arg;

        }
        else {

            // Subprogram.quoteArg() checks whether the arg is already quoted
            quotedArg = Subprogram.quoteArg(arg);

        }

        return quotedArg;
    }


    /**
     * Test two user IDs for equality.
     * If both userID Strings parse to a valid
     * javax.mail.internet.InternetAddress,
     * the user IDs match if the email addresses match, and
     * any personal name in the InternetAddress is ignored.
     * Otherwise, i.e. if one or both user IDs is not
     * a valid InternetAddress, they must match exactly.
     *
     * @param  userID1  first user ID
     * @param  userID2  second user ID
     * @return          equal
     */
    public static boolean userIDsEqual(String userID1, String userID2)
    {
        boolean match = false;

        // this requires a double-parse, but the code is now clear
        if (isInternetAddress(userID1) &&
            isInternetAddress(userID2)) {

            try {
                InternetAddress inetAddress1 = new InternetAddress(userID1);
                InternetAddress inetAddress2 = new InternetAddress(userID2);
                String emailAddress1 = inetAddress1.getAddress();
                String emailAddress2 = inetAddress2.getAddress();

                match = emailAddress1.equals(emailAddress2);
            }
            catch (javax.mail.internet.AddressException ae) {
                // IgnoredLog.getLog().println("user ID is not an internet address: " + ae.toString());
                match = false;
            }

        }
        else {
            match = userID1.equals(userID2);
        }

        return match;
    }


    private static boolean isInternetAddress(String userID)
    {
        boolean isEmail = false;

        try {
            new InternetAddress(userID);
            isEmail = true;
        }
        catch (javax.mail.internet.AddressException ae) {
            // IgnoredLog.getLog().println("user ID is not an internet address: " + userID);
            isEmail = false;
        }

        return isEmail;
    }


    /**
     * Set keyring pathnames.
     *  <p>
     *  This method is final because it is called during construction.
     *
     * @param  crypto  new keyring pathnames
     */
    public final void setKeyringPathnames(CryptoService crypto)
    {
        try {
            String name = crypto.getName();
            if (name.equals(com.goodcrypto.crypto.GPGPluginConstants.Name) ||
                name.equals(com.goodcrypto.crypto.key.GPGPluginConstants.Name)) {

                if (!(crypto instanceof GPGPlugin)) {
                    throw new CryptoException(
                        "expected GPGPlugin, but got " + crypto.getClass().getName());
                }
                GPGPlugin gpgCrypto = (GPGPlugin)crypto;

                publicKeyringPathname =
                    (new File(gpgCrypto.getHomeDir(), GPGPubKeyFilename)).
                    getAbsolutePath();
                resetPublicKeyRings();

                secretKeyringPathname =
                    (new File(gpgCrypto.getHomeDir(), GPGSecKeyFilename)).
                    getAbsolutePath();
                resetSecretKeyRings();

            }

            else if (name.equals(com.goodcrypto.crypto.PGPPluginConstants.Name) ||
                name.equals(com.goodcrypto.crypto.key.PGPPluginConstants.Name)) {

                if (!(crypto instanceof PGPPlugin)) {
                    throw new CryptoException(
                        "expected PGPPlugin, but got " + crypto.getClass().getName());
                }
                PGPPlugin pgpCrypto = (PGPPlugin)crypto;

                publicKeyringPathname =
                    (new File(pgpCrypto.getHomeDir(), PGPPubKeyFilename)).
                    getAbsolutePath();
                resetPublicKeyRings();

                secretKeyringPathname =
                    (new File(pgpCrypto.getHomeDir(), PGPSecKeyFilename)).
                    getAbsolutePath();
                resetSecretKeyRings();

            }

            else {

                setDefaultKeyringPathnames();

            }
        }
        catch (CryptoException ce) {
            getLog().print(ce);
        }
    }


    /**
     *  Sets the public keyring filename.
     *  <p>
     *  This method is final because it is called during construction.
     *
     * @param  filename  new public keyring filename
     */
    public final void setPublicKeyringPathname(String filename)
    {
        publicKeyringPathname = filename;
        resetPublicKeyRings();
    }


    /**
     *  Sets the secret keyring filename.
     *  <p>
     *  This method is final because it is called during construction.
     *
     * @param  filename  new secret keyring filename
     */
    public final void setSecretKeyringPathname(String filename)
    {
        secretKeyringPathname = filename;
        resetSecretKeyRings();
    }


    /**
     *  Reread public keyrings from disk.
     *  Keys are not actualy read until needed.
     *  <p>
     *  This method is final because it is called during construction.
     */
    public final void resetPublicKeyRings()
    {
        publicKeyringsNeedRefresh = true;
    }


    /**
     *  Reread secret keyrings from disk.
     *  Keys are not actualy read until needed.
     *  <p>
     *  This method is final because it is called during construction.
     */
    public final void resetSecretKeyRings()
    {
        secretKeyringsNeedRefresh = true;
    }


    /**
     * Returns whether the specified function is supported.
     *
     * @param  func  The function to check
     * @return       Whether the function is supported
     */
    public boolean isFunctionSupported(String func)
    {
        // this key service supports all functions
        log.println(getName() + " supports the function " + func);
        return true;
    }


    /**
     * Get the version of this plugin's implementation, i.e. the CORBA servant's version.
     * (copied from KeyService)
     *
     * @return    Plugin version
     */
    public synchronized String getPluginVersion()
    {
        return Version;
    }


    /**
     * Get the version of the underlying crypto.
     * (copied from KeyService)
     *
     * Bouncy Castle doesn't offer a version number.
     *
     * @return                      Crypto version
     * @exception  CryptoException
     */
    public synchronized String getCryptoVersion()
        throws CryptoException
    {
        return Version;
    }


    /**
     * Get the key service's name.
     * (copied from KeyService)
     *
     * @return    Name of the plugin
     */
    public synchronized String getName()
    {
        return getClass().getName();
    }


    /**
     *          Whether a key ID is valid.
     *
     * @param  userID               ID for the key. This is typically an email address.
     * @return                      Whether the key ID is valid
     * @exception  CryptoException  Crypto exception
     */
    public boolean isValid(String userID)
        throws CryptoException
    {
        boolean valid = (getPublicEncryptionKey(userID) != null);
        try {
            valid = (getPublicEncryptionKey(userID) != null);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }
        return valid;
    }


    /**
     *  Get public keys from a byte array containing a keyring.
     *
     * @param  data             Public keyring data
     * @return                  public keys
     * @exception  IOException  Description of Exception
     */
    public Iterator getPublicKeys(byte[] data)
        throws IOException
    {
        PGPPublicKeyRing keyRing = getPublicKeyRing(data);
        return keyRing.getPublicKeys();
    }


    /**
     *  Get a public keyring from a byte array.
     *
     * @param  data             Public keyring data
     * @return                  public key ring
     * @exception  IOException  Description of Exception
     */
    public PGPPublicKeyRing getPublicKeyRing(byte[] data)
        throws IOException
    {
        // getLog().println("importing keyring:\n" + new String(data));
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(data);
        InputStream decoderIn = PGPUtil.getDecoderStream(bytesIn);
        PGPPublicKeyRing keyRing = new PGPPublicKeyRing(decoderIn);
        decoderIn.close();
        return keyRing;
    }


    /**
     *  Get a list of user ids associated with a public key block.
     *
     * @param  keyBlock  ASCII armored key block
     * @return           Key user ids
     */
    public List getKeyUserIDs(String keyBlock)
    {
        return getKeyUserIDs(keyBlock.getBytes());
    }


    /**
     *  Get a list of user ids associated with a public key block.
     *
     * @param  data  Key data, usually an ascii armored public key block
     * @return       Key user ids
     */
    public List getKeyUserIDs(byte[] data)
    {
        List keyUserIDs = new Vector();

        try {
            InputStream in = new ByteArrayInputStream(data);
            List pgpObjects = getOpenPGP().getObjectList(in);

            Iterator objects = pgpObjects.iterator();
            while (objects.hasNext()) {

                Object object = objects.next();

                if (object instanceof PGPPublicKey) {

                    PGPPublicKey key = (PGPPublicKey)object;

                    Iterator userIDs = key.getUserIDs();
                    while (userIDs.hasNext()) {
                        String userID = (String)userIDs.next();
                        // getLog().println("user ID: " + userID);
                        keyUserIDs.add(userID);
                    }

                }
            }
            try {
                in.close();
            }
            catch (IOException ioe) {
                getLog().print(ioe);
            }
        }
        catch (CryptoException ce) {
            getLog().print(ce);
        }

        return keyUserIDs;
    }


    /**
     *  Gets the public keyring filename.
     *
     * @return    public keyring filename
     */
    public String getPublicKeyringPathname()
    {
        return publicKeyringPathname;
    }


    /**
     *  Gets the secret keyring filename.
     *
     * @return    secret keyring filename
     */
    public String getSecretKeyringPathname()
    {
        return secretKeyringPathname;
    }


    /**
     *  Gets the public keyring collection.
     *
     *  Ignore pmd - this already uses block level synchronization.
     *
     * @return    public keyring collection
     */
    public synchronized PGPPublicKeyRingCollection getPublicKeyRingCollection()
    {
        final boolean AlwaysReadFromDisk = true;

        if (publicKeyrings == null ||
            publicKeyringsNeedRefresh ||
            AlwaysReadFromDisk) {

            publicKeyrings = readPublicKeyRingCollection();

        }

        return publicKeyrings;
    }


    /**
     *  Gets the private encryption key.
     *
     * @param  keyID                        key ID
     * @param  passphrase                   passphrase
     * @return                              private encryption key
     * @exception  NoSuchProviderException  Description of the Exception
     * @exception  PGPException             Description of the Exception
     */
    public PGPPrivateKey getPrivateEncryptionKey(long keyID, String passphrase)
        throws NoSuchProviderException, PGPException
    {
        PGPPrivateKey privateKey = null;
        PGPSecretKey secretKey = getSecretEncryptionKey(keyID);
        if (secretKey != null) {
            privateKey = getPrivateKey(secretKey, passphrase);
        }
        return privateKey;
    }


    /**
     * Get the log used by this plugin. Subclasses should override this method.
     *
     * @return    The Log value
     */
    public Log getLog()
    {
        return log;
    }



    /**
     * Returns the first encryption key for the given userID.
     *
     * @param  userID               User ID
     * @return                      The user ID's public encryption key
     * @exception  CryptoException  crypto exception
     */
    public PGPPublicKey getPublicEncryptionKey(String userID)
        throws CryptoException
    {
        PGPPublicKey pubKey = null;

        try {
            Iterator keys = getPublicKeys(userID);
            if (!keys.hasNext()) {
                getLog().println("no pub keys for " + userID);
            }
            while (pubKey == null && keys.hasNext()) {

                PGPPublicKey key = (PGPPublicKey)keys.next();
                if (key.isEncryptionKey()) {
                    pubKey = key;
                }

            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        if (pubKey == null) {
            getLog().println("Warning: no public encyption key for " + userID);
        }

        return pubKey;
    }


    /**
     * Returns the public keys for the given userID.
     * There may be subkeys as well as a main key for a  key id.
     * A key matches the userID if userIDsEqual() returns true.
     *
     * @param  userID                     user ID
     * @return                            matching public keys
     * @exception  FileNotFoundException  keyring file not found
     * @exception  IOException            IO exception
     * @exception  PGPException           PGP exception
     */
    public Iterator getPublicKeys(String userID)
        throws FileNotFoundException, IOException, PGPException
    {
        // getLog().println("getting pub keys matching user id: " + userID);
        List pubKeys = new Vector();

        PGPPublicKeyRingCollection keyring = getPublicKeyRingCollection();

        Iterator rings = keyring.getKeyRings();
        while (rings.hasNext()) {

            PGPPublicKeyRing ring = (PGPPublicKeyRing)rings.next();

            boolean matched = false;

            Iterator keys = ring.getPublicKeys();
            while (keys.hasNext()) {

                PGPPublicKey key = (PGPPublicKey)keys.next();

                if (matched) {
                    pubKeys.add(key);
                }
                else {
                    Iterator ids = key.getUserIDs();
                    while (ids.hasNext() &&
                        !matched) {

                        String id = (String)ids.next();
                        if (userIDsEqual(id, userID)) {
                            pubKeys.add(key);
                            matched = true;
                        }

                    }
                }
            }
        }

        Iterator pubKeysIterator = pubKeys.iterator();
        if (!pubKeysIterator.hasNext()) {
            getLog().println("Warning: no public keys for " + userID);
        }

        return pubKeysIterator;
    }


    /**
     * Get secret key matching key id.
     * A key matches the userID if userIDsEqual() returns true.
     *
     * @param  keyID          key id
     * @return                matching secret key
     */
    public PGPSecretKey getSecretEncryptionKey(long keyID)
    { // throws Exception

        PGPSecretKey secretKey = null;

        Iterator keys = getSecretKeys();
        while (secretKey == null &&
            keys.hasNext()) {

            PGPSecretKey key = (PGPSecretKey)keys.next();

            if (key.getKeyID() == keyID &&
                key.getPublicKey().isEncryptionKey()) {
                secretKey = key;
            }

        }

        return secretKey;
    }


    /**
     * Get (first) secret key matching user id. Is this useful?
     * A key matches the userID if userIDsEqual() returns true.
     *
     * @param  userID         User ID
     * @return                The SecretEncryptionKey value
     */
    public PGPSecretKey getSecretEncryptionKey(String userID)
    { // throws Exception

        PGPSecretKey secretKey = null;

        Iterator keys = getSecretKeys();
        while (secretKey == null &&
            keys.hasNext()) {

            PGPSecretKey key = (PGPSecretKey)keys.next();

            Iterator keyUserIDs = key.getUserIDs();
            while (secretKey == null &&
                keyUserIDs.hasNext()) {

                String id = (String)keyUserIDs.next();
                if (userIDsEqual(id, userID) &&
                    key.getPublicKey().isEncryptionKey()) {
                    secretKey = key;
                }

            }
        }

        return secretKey;
    }


    /**
     *  Gets the secret key.
     * A key matches the userID if userIDsEqual() returns true.
     *
     * @param  userID         User ID
     * @return                secret key
     */
    public PGPSecretKey getSecretKey(String userID)
    { // throws Exception

        PGPSecretKey secretKey = null;

        Iterator keys = getSecretKeys();
        while (secretKey == null &&
            keys.hasNext()) {

            PGPSecretKey key = (PGPSecretKey)keys.next();
            logUserIDs(key);

            Iterator keyUserIDs = key.getUserIDs();
            while (secretKey == null &&
                keyUserIDs.hasNext()) {

                String id = (String)keyUserIDs.next();
                if (userIDsEqual(id, userID)) {
                    secretKey = key;
                }

            }
        }

        if (secretKey == null) {
            getLog().println("unable to get secret key for user id: " + userID);
        }

        return secretKey;
    }


    /**
     * Returns a list of all secret keys, i.e. public/private keypairs.
     *
     * @return                List of secret keys
     */
    public Iterator getSecretKeys()
    { // throws Exception

        List secretKeys = new Vector();

        PGPSecretKeyRingCollection keyring = getSecretKeyRingCollection();

        Iterator rings = keyring.getKeyRings();
        while (rings.hasNext()) {
            PGPSecretKeyRing ring = (PGPSecretKeyRing)rings.next();

            Iterator keys = ring.getSecretKeys();
            while (keys.hasNext()) {
                PGPSecretKey key = (PGPSecretKey)keys.next();
                secretKeys.add(key);
            }
        }

        return secretKeys.iterator();
    }



    /**
     * Get the private key corresponding to keyID.
     *
     * See findSecretKey() in org.bouncycastle.openpgp.examples.KeyBasedFileProcessor.
     *
     * @param  keyID                     keyID we want.
     * @param  pass                      passphrase to decrypt secret key with.
     * @return                           matching private key
     * @throws  IOException              IO exception
     * @throws  PGPException             PGP exception
     * @throws  NoSuchProviderException  if crypto service provider is not found
     */
    public PGPPrivateKey getPrivateKey(long keyID,
                                       String pass)
        throws IOException, PGPException, NoSuchProviderException
    {
        PGPPrivateKey key = null;

        PGPSecretKeyRingCollection secretKeys = getSecretKeyRingCollection();
        PGPSecretKey secKey = secretKeys.getSecretKey(keyID);
        if (secKey == null) {
            getLog().println("unable to get secret key for key id: " + Long.toHexString(keyID));
        }
        else {
            key = secKey.extractPrivateKey(pass.toCharArray(), BCProvider);
        }

        if (key == null) {
            getLog().println("unable to get private key for key id: " + Long.toHexString(keyID));
        }

        return key;
    }


    /**
     * Returns the first private key for the given userID.
     *
     * @param  userID                       User ID
     * @param  passphrase                   passphrase
     * @return                              The PublicEncryptionKey value
     * @exception  NoSuchProviderException  Description of the Exception
     * @exception  PGPException             Description of the Exception
     */
    public PGPPrivateKey getPrivateKey(String userID,
                                       String passphrase)
        throws NoSuchProviderException, PGPException
    {
        return getPrivateKey(getSecretKey(userID), passphrase);
    }


    /**
     * Returns the private key for the given secret key.
     *
     * @param  secretKey                    Secret key
     * @param  passphrase                   Passphrase
     * @return                              Private key
     * @exception  NoSuchProviderException  Description of the Exception
     * @exception  PGPException             Description of the Exception
     */
    public PGPPrivateKey getPrivateKey(PGPSecretKey secretKey,
                                       String passphrase)
        throws NoSuchProviderException, PGPException
    {
        if (LogPassphrases) {
            getLog().println("DEBUG ONLY! passphrase: " + passphrase);
        }
        return secretKey.extractPrivateKey(passphrase.toCharArray(), BCProvider);
    }


    /**
     *  Gets the secret keyring.
     *
     * @return    private keyring
     */
    public PGPSecretKeyRingCollection getSecretKeyRingCollection()
    {
        final boolean AlwaysReadFromDisk = true;

        if (secretKeyrings == null ||
            secretKeyringsNeedRefresh ||
            AlwaysReadFromDisk) {

            secretKeyrings = readSecretKeyRingCollection();

        }

        return secretKeyrings;
    }


    /**
     * Returns a list of all public keys.
     *
     * @return                            all public keys
     * @exception  FileNotFoundException  keyring file not found
     * @exception  IOException            IO exception
     * @exception  PGPException           PGP exception
     */
    public Iterator getPublicKeys()
        throws FileNotFoundException, IOException, PGPException
    {
        List publicKeys = new Vector();

        // a keyring file may contain multiple keyrings
        PGPPublicKeyRingCollection keyring = getPublicKeyRingCollection();

        Iterator rings = keyring.getKeyRings();
        while (rings.hasNext()) {
            PGPPublicKeyRing ring = (PGPPublicKeyRing)rings.next();

            Iterator keys = ring.getPublicKeys();
            while (keys.hasNext()) {
                PGPPublicKey key = (PGPPublicKey)keys.next();
                publicKeys.add(key);
            }
        }

        return publicKeys.iterator();
    }


    /**
     * Get list of user IDs.
     *
     * Some crypto engines require an exact match to an
     * existing user ID, no matter what their docs say.
     * (copied from KeyService)
     *
     * @return                      List of user IDs
     * @exception  CryptoException  crypto exception
     */
    public String[] getUserIDs()
        throws CryptoException
    {
        String[] userIDStrings = null;

        try {

            Iterator keys = getPublicKeys();
            List userIDs = new Vector();

            while (keys.hasNext()) {
                PGPPublicKey key = (PGPPublicKey)keys.next();

                Iterator keyUserIDs = key.getUserIDs();
                while (keyUserIDs.hasNext()) {
                    String id = (String)keyUserIDs.next();
                    userIDs.add(id);
                }
            }

            userIDStrings = (String[])userIDs.toArray(EmptyStringArray);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        return userIDStrings;
    }


    /**
     *    Returns a user's key fingerprint.
     *    This is the fingerprint of the first public key associated
     *    with the user ID.
     *
     * @param  userID               ID for the key. This is typically an email address.
     * @return                      Fingerprint, or null if none
     * @exception  CryptoException  crypto exception
     */
    public String getFingerprint(String userID)
        throws CryptoException
    {
        String fingerprint = null;
        
        try {
            PGPPublicKey key = getFirstPublicKey(userID);
            if (key != null) {
                fingerprint = getFingerprint(key);
            }
        }
        catch (Exception e) {
            getLog().print(e);
            throw new CryptoException(e);
        }
        
        return fingerprint;
    }


    /**
     *          Returns a key's fingerprint.
     *
     *  Fingerprints are returned as upper case hex.
     *
     * @param  key                  Public key
     * @return                      Fingerprint
     * @exception  CryptoException  crypto exception
     */
    public String getFingerprint(PGPPublicKey key)
        throws CryptoException
    {
        try {
            byte[] fpBytes = key.getFingerprint();
            getLog().println("fingerprint:");
            getLog().print(fpBytes);
            StringBuffer fingerprint = new StringBuffer();
            for (int i = 0; i < fpBytes.length; ++i) {

                String hex = Integer.toHexString((char)fpBytes[i]);

                // we want upper case, 2 chars long
                // ignore pmd and findbugs - this string should not be internationalized
                hex = hex.toUpperCase();
                while (hex.length() < 2) {
                    hex = '0' + hex;
                }
                if (hex.length() > 2) {
                    hex = hex.substring(hex.length() - 2);
                }

                fingerprint.append(hex);
            }
            return fingerprint.toString();
        }
        catch (Exception e) {
            getLog().print(e);
            throw new CryptoException(e);
        }
    }


    /**
     * Returns a default SecureRandom, so it can be reused.
     * Reusing a PRNG is a security risk.
     *
     * @return    secure random
     */
    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }


    /**
     *          Create a new public key pair.
     *
     *  Create a new key and add it to the keyring.
     * (copied from KeyService)
     *
     * @param  userID               ID for the new key. This is typically an email address.
     * @param  passphrase           Passphrase
     * @exception  CryptoException  crypto exception
     */
    public void create(String userID, String passphrase)
        throws CryptoException
    {
        final int DSAKeyLength = 1024;

        getLog().println("creating key for userID: " + userID);
        try {
            if (isValid(userID)) {
                String message = "key already exists: " + userID;
                getLog().println(message);
                throw new CryptoException(message);
            }
            else {
                // generate dsa keys
                KeyPairGenerator dsaKpg =
                    KeyPairGenerator.getInstance(DSAProvider, BCProvider);
                dsaKpg.initialize(DSAKeyLength);
                KeyPair dsaKp = dsaKpg.generateKeyPair();
                getLog().println("generated dsa key");

                // generate el gamal keys
                KeyPairGenerator elgKpg =
                    KeyPairGenerator.getInstance(ElGamalProvider, BCProvider);
                ElGamalParameterSpec elparams = generateElGamalParameters();
                elgKpg.initialize(elparams);
                KeyPair elgKp = elgKpg.generateKeyPair();
                getLog().println("generated elgamal key");

                saveKeyPair(dsaKp, elgKp, userID, passphrase);

                getLog().println("keyID of " + userID + " after create: " + getKeyID(userID));
            }
        }
        catch (CryptoException ce) {
            handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }
    }


    /**
     *          Delete a key.
     *
     *  Delete an existing key, or key pair, from the keyring.
     * (copied from KeyService)
     *
     * @param  userID               ID for the new key. This is typically an email address.
     * @exception  CryptoException  crypto exception
     */
    public void delete(String userID)
        throws CryptoException
    {
        getLog().println("deleting key for userID: " + userID);
        try {
            // isValid() says a sig only key is not valid, but we don't want to crash
            if (isValid(userID)) {

                KeyringFilter keyringFilter = new KeyringFilter(
                    getPublicKeyringPathname(),
                    getSecretKeyringPathname());

                // we wouldn't have to dup code here if bc's PGPPublicXXX and
                // PGPSecretXXX classes implemented the same interface

                // delete matching public keys
                PGPPublicKeyRingCollection publicKeyring =
                    new PGPPublicKeyRingCollection(
                    keyringFilter.getPublicIn());
                Iterator publicRings = publicKeyring.getKeyRings();
                while (publicRings.hasNext()) {

                    PGPPublicKeyRing ring =
                        (PGPPublicKeyRing)publicRings.next();
                    PGPPublicKey key = ring.getPublicKey();

                    Iterator ids = key.getUserIDs();
                    // !!!!! this assumes just one user id
                    String id = (String)ids.next();
                    if (userIDsEqual(id, userID)) {
                        getLog().println("deleting public key " +
                            Long.toHexString(key.getKeyID()) +
                            " for user id: " + id);
                    }
                    else {
                        /*
                        getLog().println("copying public key " +
                            Long.toHexString(key.getKeyID()));
                        */
                        ring.encode(keyringFilter.getPublicOut());
                    }

                }

                // delete matching secret keys
                PGPSecretKeyRingCollection secretKeyring =
                    new PGPSecretKeyRingCollection(keyringFilter.getSecretIn());
                Iterator secretRings = secretKeyring.getKeyRings();
                while (secretRings.hasNext()) {

                    PGPSecretKeyRing ring = (PGPSecretKeyRing)secretRings.next();
                    PGPSecretKey key = ring.getSecretKey();

                    Iterator ids = key.getUserIDs();
                    // !!!!! this assumes just one user id
                    String id = (String)ids.next();
                    if (userIDsEqual(id, userID)) {
                        getLog().println("deleting secret key " +
                            Long.toHexString(key.getKeyID()) +
                            " for user id: " + id);
                    }
                    else {
                        /*
                        getLog().println("copying secret key " +
                            Long.toHexString(key.getKeyID()));
                        */
                        ring.encode(keyringFilter.getSecretOut());
                    }

                }

                keyringFilter.close();
                resetPublicKeyRings();
                resetSecretKeyRings();

                if (isValid(userID)) {
                    String message = "key is still valid after delete: " + userID;
                    getLog().println(message);
                    throw new CryptoException(message);
                }

            }
            else {
                String message = "key is not valid: " + userID;
                getLog().println(message);
                throw new CryptoException(message);
            }
        }
        catch (CryptoException ce) {
            handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }
    }


    /**
     *          Export a public key.
     *
     *  Export a public key from the keyring.
     *
     * @param  userID               ID for the key. This is typically an email address.
     * @return                      Public key
     * @exception  CryptoException  crypto exception
     */
    public String exportPublic(String userID)
        throws CryptoException
    {
        String publicKey = null;

        try {
            if (isValid(userID)) {

                Iterator keys = getPublicKeys(userID);
                if (!keys.hasNext()) {
                    getLog().println("No keys found for userid:\n" + userID);
                }

                ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                BCPGOutputStream bcpgOut = new BCPGOutputStream(bytesOut);

                while (keys.hasNext()) {
                    PGPPublicKey key = (PGPPublicKey)keys.next();
                    key.encode(bcpgOut);
                }

                bcpgOut.close();

                byte[] keyBytes = bytesOut.toByteArray();
                getLog().println("keyBytes.length:\n" + keyBytes.length);
                publicKey = new String(getOpenPGP().armor(keyBytes));
                getLog().println("exporting key:\n" + publicKey);

            }
            else {
                String message = "key is not valid: " + userID;
                getLog().println(message);
                throw new CryptoException(message);
            }
        }
        catch (CryptoException ce) {
            handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
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
     * @param  data                 Public key data
     * @exception  CryptoException  Description of the Exception
     */
    public void importPublic(byte[] data)
        throws CryptoException
    {
        try {
            // getLog().println("importing key:\n" + new String(data));
            PGPPublicKeyRing keyRing = getPublicKeyRing(data);

            KeyringFilter keyringFilter = new KeyringFilter(
                getPublicKeyringPathname(),
                getSecretKeyringPathname());

            keyringFilter.copy();
            keyRing.encode(keyringFilter.getPublicOut());

            keyringFilter.close();
        }
        catch (IOException ioe) {
            throw new CryptoException(ioe);
        }
        resetPublicKeyRings();
        resetSecretKeyRings();
    }


    /**
     *  Log an error.
     *
     * @param  message              log message
     * @exception  CryptoException  Crypto Exception
     */
    public void logError(String message)
        throws CryptoException
    {
        String errorMsg = "Error: " + message;
        getLog().printStackTrace(errorMsg);
        throw new CryptoException(errorMsg);
    }


    /**
     *  Reads the public keyring collection from disk.
     *
     * @return    public keyring collection
     */
    public PGPPublicKeyRingCollection readPublicKeyRingCollection()
    {
        InputStream inFile = null;

        try {
            inFile = new FileInputStream(getPublicKeyringPathname());
            InputStream in = PGPUtil.getDecoderStream(inFile);

            if (LogKeyrings) {
                getOpenPGP().logPGPStream("public keyring collection", in);
                in.close();
                inFile.close();
                inFile = new FileInputStream(getPublicKeyringPathname());
                in = PGPUtil.getDecoderStream(inFile);
            }

            // a keyring file may contain multiple keyrings
            publicKeyrings = new PGPPublicKeyRingCollection(in);
            publicKeyringsNeedRefresh = false;

        }
        catch (Exception e) {
            getLog().print(e);
        }
        finally {
            if (inFile != null) {
                try {
                    // this assumes that "new PGPPublicKeyRingCollection"
                    // (still) reads the entire stream
                    inFile.close();
                }
                catch (IOException ignored) {
                    IgnoredLog.getLog().print(ignored);
                }
            }
        }

        return publicKeyrings;
    }


    /**
     *  Remove any existing keys that match the key.
     *  Gpg should do this itself, but doesn't.
     *  !!!!! Do we need to do this for pgp, too?
     *
     * @param  data    Key to match, usually an ascii armored public key block
     * @param  plugin  Key service crypto plugin
     */
    public void removeMatchingKeys(KeyService plugin, byte[] data)
    {
        try {
            Iterator userIDs = getKeyUserIDs(data).iterator();
            while (userIDs.hasNext()) {
                String userID = (String)userIDs.next();
                if (plugin.isValid(userID)) {
                    getLog().println("deleting old key for " + userID);
                    plugin.delete(userID);
                }
            }
        }
        catch (CryptoException ce) {
            getLog().print(ce);
        }
    }


    /**
     *  Handle a crypto exception.
     *
     * @param  ce                   Crypto exception
     * @exception  CryptoException  crypto exception
     */
    public void handleCryptoException(CryptoException ce)
        throws CryptoException
    {
        getLog().print(ce);
        throw ce;
    }


    /**
     *  Handle an unexpected exception.
     *
     * @param  t                    Throwable
     * @exception  CryptoException  Crypto exception
     */
    public void handleUnexpectedException(Throwable t)
        throws CryptoException
    {
        getLog().print(t);

        // if this is a test, stopProgram() won't actually stop the program
        com.goodcrypto.crypto.FatalError.stopProgram(t);
        throw new CryptoException(t.getMessage());
    }


    /**
     *  Read the secret keyring from disk.
     *
     * @return    private keyring
     */
    public PGPSecretKeyRingCollection readSecretKeyRingCollection()
    {
        InputStream inFile = null;

        try {
            inFile = new FileInputStream(getSecretKeyringPathname());
            InputStream in = PGPUtil.getDecoderStream(inFile);

            if (LogKeyrings) {
                getOpenPGP().logPGPStream("secret keyring collection", in);
                in.close();
                inFile.close();
                inFile = new FileInputStream(getSecretKeyringPathname());
                in = PGPUtil.getDecoderStream(inFile);
            }

            // a keyring file may contain multiple keyrings
            secretKeyrings = new PGPSecretKeyRingCollection(in);
            secretKeyringsNeedRefresh = false;

        }
        catch (Exception e) {
            getLog().print(e);
        }
        finally {
            if (inFile != null) {
                try {
                    // this assumes that "new PGPSecretKeyRingCollection"
                    // (still) reads the entire stream
                    inFile.close();
                }
                catch (IOException ignored) {
                    IgnoredLog.getLog().print(ignored);
                }
            }
        }

        return secretKeyrings;
    }


    /** Set default keyring pathnames. */
    private void setDefaultKeyringPathnames()
    {
        setPublicKeyringPathname(getKeyringPathname(BCDirName, BCPubKeyFilename));
        setSecretKeyringPathname(getKeyringPathname(BCDirName, BCSecKeyFilename));
    }



    /**
     * Returns the first public key for the given userID.
     *
     * @param  userID               User ID
     * @return                      The user ID's fiurst public key
     * @exception  CryptoException  crypto exception
     */
    private PGPPublicKey getFirstPublicKey(String userID)
        throws CryptoException
    {
        PGPPublicKey pubKey = null;

        try {
            Iterator keys = getPublicKeys(userID);
            if (keys.hasNext()) {
                pubKey = (PGPPublicKey)keys.next();
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        if (pubKey == null) {
            getLog().println("Warning: no public key for " + userID);
        }

        return pubKey;
    }


    /**
     * Get the pathname of a keyring file in the home dir.
     *
     * @param  subdirName  subdirectory under home directory
     * @param  basename    keyring filename
     * @return             Keyring pathname
     */
    private String getKeyringPathname(String subdirName, String basename)
    {
        String filename = null;

        String userHomeDir = System.getProperty("user.home");
        if (userHomeDir != null &&
            userHomeDir.length() > 0) {

            File subDir = new File(userHomeDir, subdirName);
            File file = new File(subDir, basename);

            try {
                // !!!! this creation of a filepath should be generalized somewhere
                if (subDir.exists()) {
                    if (!subDir.isDirectory()) {
                        throw new IOException(
                            "Not a directory: " + subDir.getPath());
                    }
                }
                else {
                    if (!subDir.mkdirs()) {
                        throw new IOException(
                            "Unable to create directory: " + subDir.getPath());
                    }
                }
                if (!file.exists() &&
                    !file.createNewFile()) {
                    throw new IOException(
                        "File already exists even though File.exists() returned false: " + file.getPath());
                }
            }
            catch (IOException ioe) {
                getLog().print(ioe);
            }

            filename = file.getAbsolutePath();
        }

        return filename;
    }


    private String getKeyID(String userID)
        throws CryptoException
    {
        try {
            PGPPublicKey key = getPublicEncryptionKey(userID);
            if (key == null) {
                throw new CryptoException("No public encryption key for " + userID);
            }
            return Long.toHexString(key.getKeyID());
        }
        catch (Exception e) {
            getLog().print(e);
            throw new CryptoException(e);
        }
    }


    private OpenPGP getOpenPGP()
    {
        if (openpgp == null) {
            openpgp = new OpenPGP(
                getPublicKeyringPathname(),
                getSecretKeyringPathname());
        }
        return openpgp;
    }


    private void logUserIDs(PGPSecretKey key)
    {
        Iterator keyUserIDs = key.getUserIDs();
        if (keyUserIDs.hasNext()) {
            getLog().println("user ids for key id " + Long.toHexString(key.getKeyID()) + ":");
            while (keyUserIDs.hasNext()) {
                String id = (String)keyUserIDs.next();
                getLog().println("    " + id);
            }
        }
        else {
            getLog().println("No user ids for secret key id " + Long.toHexString(key.getKeyID()));
            getLog().println("Matching public key id is " + Long.toHexString(key.getPublicKey().getKeyID()));
        }
    }


    /**
     * Log the user IDs for this key.
     *
     * Findbugs notes that this method is not called, but it is sometimes
     * used for debugging.
     *
     * @param  key  public key
     */
    private void logUserIDs(PGPPublicKey key)
    {
        Iterator keyUserIDs = key.getUserIDs();
        if (keyUserIDs.hasNext()) {
            getLog().println("user ids for key id " + Long.toHexString(key.getKeyID()) + ":");
            while (keyUserIDs.hasNext()) {
                String id = (String)keyUserIDs.next();
                getLog().println("    " + id);
            }
        }
        else {
            getLog().println("WARNING: no user ids for public key id " + Long.toHexString(key.getKeyID()));
        }
    }


    private void saveKeyPair(KeyPair dsaKp,
                             KeyPair elgKp,
                             String userID,
                             String passphrase)
        throws IOException,
        InvalidKeyException,
        NoSuchProviderException,
        SignatureException,
        PGPException
    {
        PGPKeyPair dsaKeyPair =
            new PGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date(), BCProvider);
        PGPKeyPair elgKeyPair =
            new PGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date(), BCProvider);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            dsaKeyPair,
            userID,
            PGPEncryptedData.AES_256,
            passphrase.toCharArray(),
            null,
            null,
            new SecureRandom(),
            BCProvider);
        keyRingGen.addSubKey(elgKeyPair);

        KeyringFilter keyringFilter = new KeyringFilter(
            getPublicKeyringPathname(),
            getSecretKeyringPathname());
        keyringFilter.copy();

        keyRingGen.generatePublicKeyRing().encode(keyringFilter.getPublicOut());
        keyRingGen.generateSecretKeyRing().encode(keyringFilter.getSecretOut());

        keyringFilter.close();
        resetPublicKeyRings();
        resetSecretKeyRings();
    }


    /**
     * See org.bouncycastle.jce.provider.test.ElGamalTest.
     *
     * @return                                    El Gamal params
     * @exception  NoSuchAlgorithmException       no such algorithm Exception
     * @exception  NoSuchProviderException        no such provider Exception
     * @exception  InvalidParameterSpecException  invalid key generation parameter Exception
     */
    private ElGamalParameterSpec generateElGamalParameters()
        throws NoSuchAlgorithmException,
        NoSuchProviderException,
        InvalidParameterSpecException
    {
        final int KeySize = 256; // !!!!! enough?

        return generateElGamalParametersBC(KeySize);
        // return generateElGamalParametersBC(KeySize + 1);
        // return generateElGamalParametersHardcoded();
    }


    /**
     * See org.bouncycastle.jce.provider.test.ElGamalTest.
     *
     * @param  keysize                            key size in bits
     * @return                                    El Gamal parameters
     * @exception  NoSuchAlgorithmException       no such algorithm Exception
     * @exception  NoSuchProviderException        no such provider Exception
     * @exception  InvalidParameterSpecException  invalid key generation parameter Exception
     */
    private ElGamalParameterSpec generateElGamalParametersBC(int keysize)
        throws NoSuchAlgorithmException,
        NoSuchProviderException,
        InvalidParameterSpecException
    {
        /*
           If you ask the BC implementation from
           crypto-124/bcpg-jdk13-125b04 for a keysize of 256, internally
           it tries to generate a BigInteger of keysize-1, or 255. On kaffe,
           what it gets is a BigInteger of 256. This results in an infinite loop.
       */
        // generate el gamal p and g params
        AlgorithmParameterGenerator a =
            AlgorithmParameterGenerator.getInstance(ElGamalProvider, BCProvider);
        a.init(keysize, secureRandom);
        getLog().println("initialized elgamal key generator");
        AlgorithmParameters params = a.generateParameters();
        getLog().println("generated elgamal key params");
        return (ElGamalParameterSpec)params.getParameterSpec(ElGamalParameterSpec.class);
    }


    /**
     * See org.bouncycastle.jce.provider.test.ElGamalTest.
     *
     * Ignore pmd - this method is sometimes used in testing.
     *
     * @return                                    El Gamal parameters
     * @exception  NoSuchAlgorithmException       no such algorithm Exception
     * @exception  NoSuchProviderException        no such provider Exception
     * @exception  InvalidParameterSpecException  invalid key generation parameter Exception
     */
    private ElGamalParameterSpec generateElGamalParametersBCfixed()
        throws NoSuchAlgorithmException,
        NoSuchProviderException,
        InvalidParameterSpecException
    {
        // regenerating the parameters is slow, but this shortcut,
        // used throughout bc, is a major security risk
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
        return new ElGamalParameterSpec(p, g);
    }


    /**
     * See org.bouncycastle.openpgp.examples.DSAElGamalKeyRingGenerator.
     *
     * Ignore pmd - this method is sometimes used in testing.
     *
     * @return                                    El Gamal parameters
     * @exception  NoSuchAlgorithmException       no such algorithm Exception
     * @exception  NoSuchProviderException        no such provider Exception
     * @exception  InvalidParameterSpecException  invalid key generation parameter Exception
     */
    private ElGamalParameterSpec generateElGamalParametersHardcoded()
        throws NoSuchAlgorithmException,
        NoSuchProviderException,
        InvalidParameterSpecException
    {
        // regenerating the parameters is slow, but this shortcut,
        // used throughout bc, is a major security risk
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
        return new ElGamalParameterSpec(p, g);
    }

}


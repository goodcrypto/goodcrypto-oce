package com.goodcrypto.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.List;

import com.goodcrypto.io.IgnoredLog;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPV3SignatureGenerator;

/**
 * Bouncy Castle crypto plugin.
 * <p>
 * Any generic OpenPGP methods should be in the OpenPGP or OpenPGPAnalyzer class.
 * <p>
 * Bc calls the keys associated with a single userID a "keyring".
 * What gpg calls a keyring, bc calls a "keyring collection".
 * In bc, a "secret key" is a public/private key pair and a
 * "private key" is the private key of a pair.
 * We use bc's terminology here.
 * <p>
 * By convention, all keys on a keyring are for the same user id or user ids.
 * The first key on a keyring is the primary, or master, key. The others are subkeys.
 * The master key is assumed to be a signing key.
 * The others are generally assumed to be encryption keys,
 * but we double check in this class with isEncryptionKey().
 * (Do these assumptions hold for OpenPGP, GPG, and PGP?)
 * <p>
 * BC's PGPPublicKeyRing.getPublicKey(), without parameters, returns the first public
 * key in the ring. When would this be used?
 * <p>
 * In verify() and getPGPSignature() we explicitly check whether the data is armored,
 * and handle it differently if it is. Why can't we just use PGPUtil.getDecoderStream()?
 * That's what we do anyway if the data isn't armored.
 * <p>
 * It's important that all generators, streams, etc, are explicitly closed, and in
 * the right order.
 * <p>
 * Much of this code would be clearer if it consistently handled streams instead of
 * byte arrays. That's true of the crypto plugins in general.
 * <p>
 * We need a better way to handle the checks for PGPCompressedData.
 * There are multiple places where we assume just one signature.
 * <p>
 * "Error constructing key" when we call signEncryptAndArmor usually means a bad passphrase.
 * <p>
 * <h2>BouncyCastle bugs:</h2>
 * According to our tests, as BC releases came out PGPSignatureGenerator
 * worked, then stopped working at all, then worked again mostly. Currently
 * (crypto 126 with bcpg 127)
 * BC's PGPSignatureGenerator generates clearsigned signatures that are
 * unverifiable by BC itself about 4% of the time.
 * The binary signatures seem fine. Is V3 less secure?
 * Does this mean we can't accept more recent sigs?
 * The list message said they genned a sig with bc and could not verify it
 * with pgp, which implies the challenge is in generation, not verification,
 * And the fact that binary sigs seem to work may narrow it further to
 * clearsigned sig generation, particularly since changing the generator
 * class seems to help. We don't test binary sigs as thoroughly as
 * we do clearsigned.
 * Possible workarounds:
 * <ol>
 *   <li> try signing right away with a new key and regen if it fails
 *   <li> verify every sig and if it fails resign, then if it fails again
 *        tell the user
 *   <li> using version 3 sigs may help
 * </ol>
 * <p>
 * Rarely, BC allows signing with a bad passphrase.
 * It may produce secret keys unprotected by any passphrase,
 * or one or more test machines may be cracked.
 * This happens when using V3 sigs, possibly not V4.
 * A possible workaround is to test signing keys as soon as they're
 * generated to see if they can be used with a bad passphrase,
 * and regenerate them if they can.
 * <p>
 * BC uses both upper and lower case at different times to refer to the provider.
 * This causes challenges for some java.security implementations.
 * <p>
 * Verify in current BC: Leading bit accepted from BigInteger in prng is
 * always 1. This cuts the strength in half. A better algorithm is to
 * scan for the first 1 bit and throw it away. This avoids leading nulls
 * in prngs without losing entropy. It should also catch prng bitstreams of
 * all nulls, such as the famous one in pgp for linux.
 * <p>
 * Encrypting then decrypting with openpgp results in leading junk bytes.
 * The workaround is to use ASCII armor, i.e.
 * <code>signEncryptAndArmor()</code>.
 *
 * <p>Copyright 2004 GoodCrypto
 * <br>Last modified: 2007.04.19
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class BCPlugin
     extends AbstractPlugin
     implements Constants, BCConstants, com.goodcrypto.crypto.test.Constants
{
    private final static boolean Debugging = false;
    private final static String DoubleQuote = "\"";
    private final static boolean Clearsign = true;
    private final static boolean NoClearsign = false;

    private static Log log = new LogFile();

    protected OpenPGP openpgp;


    /** Creates a new BCPlugin object. */
    public BCPlugin()
    {
        Security.addProvider(new BouncyCastleProvider());

        openpgp = new OpenPGP(this);

        log.println("Ready");
    }


    /**
     * just for testing
     *
     * @param  args  Command line arguments
     */
    public static void main(String args[])
    {
        BCPlugin plugin = new BCPlugin();
        try {
            log.println("Adding Test key");
            com.goodcrypto.crypto.key.BCPlugin keyPlugin =
                new com.goodcrypto.crypto.key.BCPlugin();
            keyPlugin.create(TestUser, TestPassphrase);

            byte[] signedData = plugin.sign(TestDataString.getBytes(), TestUser, TestPassphrase);
            plugin.verify(signedData, TestUser);
        }
        catch (CryptoException ce) {
            log.println(ce);
            System.err.println(ce);
            try {
                plugin.handleUnexpectedException(ce);
            }
            catch (Exception ignored) {
                IgnoredLog.getLog().print(ignored);
            }
        }
    }


    private static void logError(String message)
        throws CryptoException
    {
        String errorMsg = "Error: " + message;
        log.printStackTrace(errorMsg);
        throw new CryptoException(errorMsg);
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
        String versionNumber = null;
        try {
            // Bouncy Castle doesn't offer a version number, but this goes boom if there is none
            versionNumber = org.bouncycastle.openpgp.PGPUtil.getDefaultProvider();
            log.println("version number is " + versionNumber);
        }
        catch (Exception e) {
            log.print(e);
        }
        return versionNumber;
    }


    /**
     * Get the plugin's name.
     * (copied from KeyService)
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
     * @return    Plugin version
     */
    public synchronized String getPluginVersion()
    {
        return "0.1";
    }


    /**
     * Determine if the crypto app is installed.
     * (copied from KeyService)
     * <p>
     * Since the BC library is dynamically loaded in
     * the constructor, it's essential to
     * enclose this plugin's constructor in try/catch.
     * If would be better if this method were static,
     * but this interface is dynamically generated from idl
     * and we can't specify "static" in an idl file.
     *
     * @return    true if backend app is available.
     */
    public synchronized boolean isAvailable()
    {
        final String TestClassname = "org.bouncycastle.openpgp.PGPPublicKey";

        boolean installed = false;

        try {
            Class bcClass = Class.forName(TestClassname);
            installed = bcClass.getName().equals(TestClassname);
            if (!installed) {
                log.println("Class.forName(" + TestClassname + ") returned class " + bcClass.getName());
            }
        }
        catch (Exception e) {
            log.println("BouncyCastle is not available");
        }

        return installed;
    }


    /**
     * Get signer of data.
     * (copied from KeyService)
     * !!!!! This assumes just one signer.
     *
     * @param  data                 Signed data
     * @return                      ID of the apparent signer, or null if none.
     * @exception  CryptoException
     */
    public synchronized String getSigner(byte[] data)
        throws CryptoException
    {
        String signer = null;

        try {
            PGPPublicKeyRingCollection keyrings = openpgp.getPublicKeyRingCollection();
            PGPSignature sig = openpgp.getPGPSignature(data);
            PGPPublicKey key = keyrings.getPublicKey(sig.getKeyID());

            Iterator keyUserIDs = key.getUserIDs();
            // !!!!! this assumes just one user id
            if (keyUserIDs.hasNext()) {
                signer = (String)keyUserIDs.next();
            }
            /*
            while (keyUserIDs.hasNext()) {
                String id = (String) keyUserIDs.next();
                userIDs.add(id);
            }
            */
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        if (signer == null) {
            logError("Could not get signer");
        }

        return signer;
    }


    /**
     * Get list of user IDs.
     *
     * Some crypto engines require an exact match to an
     * existing user ID, no matter what their docs say.
     * (copied from KeyService)
     *
     * @return                      List of user IDs
     * @exception  CryptoException
     */
    public synchronized String[] getUserIDs()
        throws CryptoException
    {
        return openpgp.getUserIDs();
    }


    /**
     * Decrypt data.
     * (copied from KeyService)
     *
     * @param  data                 Data to decrypt
     * @param  passphrase           Passphrase
     * @return                      Decrypted data
     * @exception  CryptoException
     */
    public synchronized byte[] decrypt(byte[] data,
                                       String passphrase)
        throws CryptoException
    {
        // Much of this is originally from
        //     org.bouncycastle.openpgp.examples.KeyBasedFileProcessor
        // and
        //     org.bouncycastle.openpgp.test.PGPDSAElGamalTest
        byte[] decryptedData = null;

        try {
            if (Debugging) {
                log.println("decrypting:");
                if (LogPassphrases) {
                    log.println("DEBUG ONLY! passphrase: " + passphrase);
                }
                log.print("data", data);
                // openpgp.logPGPData("decrypting", data, passphrase);
            }

            InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(data));

            PGPObjectFactory objects = new PGPObjectFactory(in);
            Object o = OpenPGP.getFirstObject(objects);

            // if compressed, switch to the decompressed objects
            if (o instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData)o;
                objects = new PGPObjectFactory(compressedData.getDataStream());
                log.println("decompressed 1");
                o = OpenPGP.getFirstObject(objects);
            }

            PGPEncryptedDataList enc;
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList)o;
            }
            else {
                log.println("Warning: unexpected packet " + o.getClass().getName());
                enc = (PGPEncryptedDataList)objects.nextObject();
            }

            if (enc.isEmpty()) {
                throw new IllegalArgumentException("Nothing to decrypt.");
            }

            List decryptedList = openpgp.getDecryptedDataList(enc, passphrase);
            Iterator cryptedObjects = decryptedList.iterator();
            o = cryptedObjects.next();

            while (!(o instanceof PGPLiteralData)) {

                if (o instanceof PGPOnePassSignatureList) {
                    openpgp.logSignatures((PGPOnePassSignatureList)o);
                }

                if (!cryptedObjects.hasNext()) {
                    throw new CryptoException("Unable to decrypt. Possibly bad passphrase, or encrypted with different plugin.");
                }
                o = cryptedObjects.next();
            }
            // the next object is the decrypted data
            o = cryptedObjects.next();

            decryptedData = (byte[])o;
            if (Debugging) {
                log.println("decrypted data:");
                log.print(decryptedData);
            }

            if (!verifyBinary(decryptedList)) {
                throw new PGPException("Message failed integrity check");
            }

            in.close();
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            openpgp.handleCryptoException(new CryptoException(e));
        }

        return decryptedData;
    }


    /**
     * Encrypt data with the public key indicated by toUserID.
     * (copied from KeyService)
     *
     * @param  data                 Data to encrypt
     * @param  toUserID             ID indicating which public key to use. This is typically an email address.
     * @return                      Encrypted data
     * @exception  CryptoException
     */
    public synchronized byte[] encryptOnly(byte[] data,
                                           String toUserID)
        throws CryptoException
    {
        byte[] encryptedData = null;

        try {
            byte[] literalData = openpgp.wrapLiteral(data);
            final boolean IsSigned = false;
            encryptedData = encrypt(literalData, IsSigned, toUserID);
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        // openpgp.logPGPData("encrypted ONLY", encryptedData);

        return encryptedData;
    }


    /**
     * Sign data with the private key indicated by userID.
     * (copied from KeyService)
     *
     * @param  data                 Data to sign
     * @param  userID               ID indicating which private key to use. This is typically an email address.
     * @param  passphrase           Passphrase
     * @return                      Signed data
     * @exception  CryptoException
     */
    public synchronized byte[] sign(byte[] data,
                                    String userID,
                                    String passphrase)
        throws CryptoException
    {
        return sign(data, userID, passphrase, Clearsign);
    }


    /**
     * Sign data with the private key indicated by fromUserID, then encrypt with
     * the public key indicated by toUserID.
     *
     * To avoid a security bug in OpenPGP we must sign before encrypting.
     * (copied from KeyService)
     *
     * @param  data                 Data to encrypt
     * @param  fromUserID           ID indicating which private key to use. This is typically your own email address.
     * @param  toUserID             ID indicating which public key to use. This is typically an email address.
     * @param  passphrase           Passphrase
     * @return                      Encrypted data
     * @exception  CryptoException
     */
    public synchronized byte[] signAndEncrypt(byte[] data,
                                              String fromUserID,
                                              String toUserID,
                                              String passphrase)
        throws CryptoException
    {
        byte[] encryptedData = null;

        log.println(
            "signing by \"" + fromUserID +
            "\" and encrypting to \"" + toUserID + DoubleQuote);

        try {
            byte[] literalData = openpgp.wrapLiteral(data);
            byte[] signedData = sign(literalData, fromUserID, passphrase, NoClearsign);
            final boolean IsSigned = true;
            encryptedData = encrypt(signedData, IsSigned, toUserID);
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        // openpgp.logPGPData("signed and encrypted", encryptedData);

        return encryptedData;
    }


    /**
     * Sign data with the private key indicated by fromUserID, then encrypt with
     * the public key indicated by toUserID, then ASCII armor.
     *
     * To avoid a security bug in OpenPGP we must sign before encrypting.
     * We can't just call signAndEncrypt() or encryptOnly() because only the innermost
     * pgp packet is supposed to be a literal packet.
     *
     * (copied from KeyService)
     *
     * @param  data                 Data to encrypt
     * @param  fromUserID           ID indicating which private key to use. This is typically your own email address.
     * @param  toUserID             ID indicating which public key to use. This is typically an email address.
     * @param  passphrase           Passphrase
     * @return                      Encrypted data
     * @exception  CryptoException
     */
    public synchronized byte[] signEncryptAndArmor(byte[] data,
                                                   String fromUserID,
                                                   String toUserID,
                                                   String passphrase)
        throws CryptoException
    {
        byte[] armoredData = null;

        if (Debugging) {
            log.println("signing by \"" + fromUserID +
                "\" and encrypting to \"" + toUserID +
                "\" and armoring");
            log.print(data);
        }

        try {
            /* if the low level doesn't wrap the data in a literal packet as needed,
                then we need to do it here
                byte[] literalData = wrapLiteral(data);
                byte[] signedData = sign(literalData, fromUserID, passphrase, NoClearsign);
            */
            byte[] signedData = sign(data, fromUserID, passphrase, NoClearsign); //DEBUG
            final boolean IsSigned = true;
            byte[] encryptedData = encrypt(signedData, IsSigned, toUserID);
            armoredData = openpgp.armor(encryptedData);
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        // openpgp.logPGPData("signed, encrypted, and armored", armoredData);

        return armoredData;
    }


    /**
     * Verify data was signed by userID.
     * (copied from KeyService)
     *
     * @param  data                 Data to verify
     * @param  byUserID             ID indicating which public key to use.
     * This is typically an email address.
     * @return                      Whether data was signed by userID
     * @exception  CryptoException
     */
    public synchronized boolean verify(byte[] data,
                                       String byUserID)
        throws CryptoException
    {
        boolean verified = false;

        log.println("verifying whether data was signed by " + byUserID);

        try {
            // ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            if (openpgp.isClearSigned(data)) {
                log.println("clearsigned");
                log.print("verifying sig", data);
                verified = verifyClearSigned(data);
            }
            else {
                log.println("not clearsigned");
                // openpgp.logPGPData("verifying sig", data);
                verified = verifyBinary(data);
            }

            if (verified) {
                log.println("verified; getting signer");
                String signer = getSigner(data);
                log.println("signer: " + signer);
                verified = signer.equals(byUserID);
                if (!verified) {
                    log.println("Could not verify because signed by \"" +
                        signer + "\", not \"" + byUserID + DoubleQuote);
                }
            }
            else {
                logError("Could not verify");
            }
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            verified = false;
            handleUnexpectedException(e);
        }

        return verified;
    }


    /**
     * Get the log used by this plugin. Subclasses should override this method.
     *
     * @return    The Log value
     */
    protected Log getLog()
    {
        return log;
    }


    /**
     * Sign data with the private key indicated by userID.
     * (copied from KeyService)
     *
     * @param  data                 Data to sign
     * @param  userID               ID indicating which private key to use. This is typically an email address.
     * @param  passphrase           Passphrase
     * @param  clearsign            Whether to clearsign the data
     * @return                      Signed data
     * @exception  CryptoException
     */
    private byte[] sign(byte[] data,
                        String userID,
                        String passphrase,
                        boolean clearsign)
        throws CryptoException
    {
        // Much of this is originally from
        //     org.bouncycastle.openpgp.examples.SignedFileProcessor
        byte[] signedData = null;

        log.println("signing data by " + userID);
        if (LogPassphrases) {
            log.println("DEBUG ONLY! passphrase: " + passphrase);
        }
        try {
            PGPSecretKey secretKey = openpgp.getSecretKey(userID);
            if (secretKey == null) {
                throw new CryptoException("No secret key found for " + userID);
            }
            PGPPrivateKey privateKey;
            try {
                privateKey = openpgp.getPrivateKey(userID, passphrase);
            }
            catch (PGPException pgpe) {
                // this is almost always a bad passphrase
                log.print(pgpe);
                throw new IllegalArgumentException("Bad passphrase, or corrupt secret keyring");
            }

            PGPV3SignatureGenerator sigGenerator =
                new PGPV3SignatureGenerator(PGPPublicKey.DSA, PGPUtil.SHA1, BCProvider);

            if (clearsign) {
                signedData = signClearsigned(data, sigGenerator, privateKey);
            }
            else {
                signedData = signBinary(data, sigGenerator, privateKey);
            }

            // PGPSignatureGenerator apparently doesn't have a close
            // sigGenerator.close();
        }
        catch (CryptoException ce) {
            openpgp.handleCryptoException(ce);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        if (clearsign) {
            log.print("signed", signedData);
        }
        /*
        else {
            openpgp.logPGPData("signed", signedData);
        }
        */
        return signedData;
    }


    /**
     * Sign binary data.
     * (copied from KeyService)
     *
     * @param  data                 Data to sign
     * @param  sigGenerator         BC signature generator
     * @param  privateKey           Signer's private key
     * @return                      Signed data
     * @exception  CryptoException  Description of the Exception
     */
    private byte[] signBinary(byte[] data,
                              PGPV3SignatureGenerator sigGenerator,
                              PGPPrivateKey privateKey)
        throws CryptoException
    {
        // Much of this is originally from
        //     org.bouncycastle.openpgp.examples.SignedFileProcessor
        byte[] signedData = null;
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();

        log.println("signing binary message");

        try {
            // create output stream
            PGPCompressedDataGenerator compressedData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);
            BCPGOutputStream pgpOut = new BCPGOutputStream(compressedData.open(bytesOut));

            // start one pass sig
            sigGenerator.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);
            sigGenerator.generateOnePassVersion(false).encode(pgpOut);

            // write data
            byte[] literalData = openpgp.wrapLiteral(data);
            pgpOut.write(literalData);

            // write sig
            sigGenerator.update(data);
            PGPSignature sig = sigGenerator.generate();
            sig.encode(pgpOut);

            pgpOut.close();
            bytesOut.close();
            compressedData.close();
        }
        catch (Exception e) {
            throw new CryptoException(e);
        }

        signedData = bytesOut.toByteArray();

        return signedData;
    }


    /**
     * Sign binary data with the private key indicated by userID.
     * (copied from KeyService)
     *
     * @param  data                 Data to sign
     * @param  sigGenerator         BC signature generator
     * @param  privateKey           Signer's private key
     * @return                      Signed data
     * @exception  CryptoException  Description of the Exception
     */
    private byte[] signClearsigned(byte[] data,
                                   PGPV3SignatureGenerator sigGenerator,
                                   PGPPrivateKey privateKey)
        throws CryptoException
    {
        // Much of this is originally from
        //     org.bouncycastle.openpgp.examples.ClearsignedFileProcessor

        log.println("clearsigning message");

        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        try {
            ArmoredOutputStream armoredOut = new ArmoredOutputStream(bytesOut);

            // start cleartext
            armoredOut.beginClearText(PGPUtil.SHA1);

            // start sig
            sigGenerator.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);

            // we insist on a final \n for the cleartext
            byte[] terminatedData;
            if (data.length > 0 && data[data.length - 1] == '\n') {
                terminatedData = data;
            }
            else {
                byte[] newData = new byte[data.length + 1];
                System.arraycopy(data, 0, newData, 0, data.length);
                newData[data.length] = '\n';
                terminatedData = newData;
            }

            // write original text
            // we do not include any final \n in the sig calculation
            byte ch = 0;
            boolean newLine = false;
            for (int index = 0; index < terminatedData.length; ++index) {

                ch = terminatedData[index];

                armoredOut.write(ch);

                if (newLine) {
                    sigGenerator.update((byte)'\n');
                    newLine = false;
                }
                if (ch == '\n') {
                    newLine = true;
                }

                if (!newLine) {
                    sigGenerator.update((byte)ch);
                }
            }

            armoredOut.endClearText();

            // generate sig
            BCPGOutputStream pgpOut = new BCPGOutputStream(armoredOut);
            PGPSignature sig = sigGenerator.generate();
            sig.encode(pgpOut);

            pgpOut.close();
            armoredOut.close();
            bytesOut.close();
        }
        catch (Exception e) {
            throw new CryptoException(e);
        }

        byte[] signedData = bytesOut.toByteArray();

        return signedData;
    }


    /**
     * Verify binary data was signed correctly.
     *
     * @param  data                 Data to verify
     * @return                      Whether data was signed
     * @exception  CryptoException  Description of the Exception
     */
    private boolean verifyBinary(byte[] data)
        throws CryptoException
    {
        InputStream in = new ByteArrayInputStream(data);
        return verifyBinary(in);
    }


    /**
     * Verify binary data was signed correctly.
     *
     * @param  in                   data to verify
     * @return                      Whether data was signed
     * @exception  CryptoException  Description of the Exception
     */
    private boolean verifyBinary(InputStream in)
        throws CryptoException
    {
        // See org.bouncycastle.openpgp.examples.SignedFileProcessor
        boolean verified = false;

        try {
            openpgp.logPGPStream("verify binary", in);
            InputStream decodedIn = PGPUtil.getDecoderStream(in);

            PGPObjectFactory pgpFact = new PGPObjectFactory(decodedIn);
            Object o = OpenPGP.getFirstObject(pgpFact);

            // if compressed, switch to the decompressed objects
            if (o instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData)o;
                pgpFact = new PGPObjectFactory(compressedData.getDataStream());
                log.println("decompressed 1");
                o = OpenPGP.getFirstObject(pgpFact);
            }

            PGPOnePassSignatureList opsList;
            if (o instanceof PGPOnePassSignatureList) {
                opsList = (PGPOnePassSignatureList)o;
            }
            else {
                log.println("Warning: unexpected object: " + o.getClass().getName());
                opsList = (PGPOnePassSignatureList)pgpFact.nextObject();
            }
            // !!!!! this assumes just one sig
            PGPOnePassSignature ops = opsList.get(0);

            PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();
            InputStream literalDataIn = literalData.getInputStream();

            // !!!!! why do we call getDecoderStream here, and
            //       not for keyring when ascii armored?
            // PGPPublicKeyRingCollection pgpRing =
            //     new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
            PGPPublicKeyRingCollection keyrings =
                openpgp.getPublicKeyRingCollection();

            PGPPublicKey key = keyrings.getPublicKey(ops.getKeyID());

            ops.initVerify(key, BCProvider);

            int ch = literalDataIn.read();
            while (ch >= 0) {
                ops.update((byte)ch);
                ch = literalDataIn.read();
            }

            PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
            PGPSignature sig = sigList.get(0);

            verified = ops.verify(sig);
        }
        // PGPException, IOException, NoSuchProviderException, SignatureException
        catch (Exception e) {
            throw new CryptoException(e);
        }

        return verified;
    }


    /**
     * Verify binary data was signed correctly.
     *
     * @param  dataList                     Data to verify
     * @return                              Whether data was signed
     * @exception  PGPException             Description of the Exception
     * @exception  NoSuchProviderException  Description of the Exception
     * @exception  SignatureException       Description of the Exception
     */
    private boolean verifyBinary(List dataList)
        throws PGPException, NoSuchProviderException, SignatureException
    {
        // See org.bouncycastle.openpgp.examples.SignedFileProcessor
        PGPOnePassSignature ops = null;

        Iterator cryptedObjects = dataList.iterator();
        Object o = cryptedObjects.next();

        while (!(o instanceof PGPOnePassSignatureList)) {
            o = cryptedObjects.next();
        }

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList)o;
        // !!!!! this assumes just one sig
        ops = opsList.get(0);

        o = cryptedObjects.next();

        while (!(o instanceof PGPLiteralData)) {
            o = cryptedObjects.next();
        }

        o = cryptedObjects.next();
        byte[] decryptedData = (byte[])o;
        ByteArrayInputStream decryptedDataIn =
            new ByteArrayInputStream(decryptedData);

        PGPPublicKeyRingCollection keyrings = openpgp.getPublicKeyRingCollection();
        PGPPublicKey key = keyrings.getPublicKey(ops.getKeyID());

        ops.initVerify(key, BCProvider);

        int ch = decryptedDataIn.read();
        while (ch >= 0) {
            ops.update((byte)ch);
            ch = decryptedDataIn.read();
        }

        PGPSignatureList sigList = (PGPSignatureList)cryptedObjects.next();
        // !!!!! this assumes just one sig
        PGPSignature sig = sigList.get(0);

        return ops.verify(sig);
    }


    /**
     * Verify clearsigned data was signed correctly.
     *
     * @param  data                         Data to verify
     * @return                              Whether data was signed
     * @exception  PGPException             Description of the Exception
     * @exception  IOException              Description of the Exception
     * @exception  NoSuchProviderException  Description of the Exception
     * @exception  SignatureException       Description of the Exception
     */
    private boolean verifyClearSigned(byte[] data)
        throws PGPException, IOException, NoSuchProviderException, SignatureException
    {
        // See org.bouncycastle.openpgp.examples.ClearSignedFileProcessor

        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        InputStream in = new ByteArrayInputStream(data);
        ArmoredInputStream armoredIn = new ArmoredInputStream(in);
        // we do not include any final \n in the sig calculation
        int ch = armoredIn.read();
        boolean newLine = false;
        while (ch >= 0 && armoredIn.isClearText()) {

            if (newLine) {
                bytesOut.write((byte)'\n');
                newLine = false;
            }
            if (ch == '\n') {
                newLine = true;
            }

            if (!newLine) {
                bytesOut.write((byte)ch);
            }

            ch = armoredIn.read();
        }

        PGPPublicKeyRingCollection keyrings = openpgp.getPublicKeyRingCollection();

        PGPObjectFactory pgpFact = new PGPObjectFactory(armoredIn);
        PGPSignatureList sigList = (PGPSignatureList)OpenPGP.getFirstObject(pgpFact);

        if (sigList.size() != 1) {
            log.println("number of signatures: " + sigList.size());
        }

        // !!!!! this assumes just one sig
        PGPSignature sig = sigList.get(0);
        long keyID = sig.getKeyID();
        log.println("signed by keyID: " + Long.toHexString(keyID));
        PGPPublicKey key = keyrings.getPublicKey(keyID);
        sig.initVerify(key, BCProvider);
        sig.update(bytesOut.toByteArray());

        return sig.verify();
    }


    /**
     * Encrypt data with the public key indicated by toUserID.
     *
     * Notice that you can encrypt without a passphrase, because all you need is
     * someone's <i>public</i> key. What you can't do without a passphrase is sign, or decrypt.
     * Those operations require a private key, and private keys should always be
     * protected by a passphrase.
     *
     * @param  data                                       Data to encrypt
     * @param  toUserID                                   ID indicating which public key to use. This is typically an email address.
     * @param  isSigned                                   Whether the data is signed
     * @return                                            Encrypted data
     * @exception  CryptoException
     * @exception  IOException
     * @exception  PGPException
     * @exception  java.security.NoSuchProviderException
     */
    private byte[] encrypt(byte[] data,
                           boolean isSigned,
                           String toUserID)
        throws IOException, CryptoException, PGPException, java.security.NoSuchProviderException
    {
        byte[] encryptedData = null;
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();

        if (Debugging) {
            log.println("encrypting to \"" + toUserID + DoubleQuote);
        }
        if (openpgp.isAsciiArmored(data)) {
            log.printStackTrace("Warning: encrypting ascii-armored data");
        }
        if (isSigned) {
            log.println("data is signed");
        }

        // there are so many variants on Triple DES,
        // for compatibility we settled on CAST5
        PGPEncryptedDataGenerator encryptor =
            new PGPEncryptedDataGenerator(PGPEncryptedDataGenerator.CAST5,
            isSigned,
            openpgp.getSecureRandom(),
            BCProvider);
        PGPPublicKey key = openpgp.getPublicEncryptionKey(toUserID);
        if (key == null) {
            throw new CryptoException("unable to get public encryption key for " + toUserID);
        }
        if (Debugging) {
            log.println("encrypting to keyID: " + Long.toHexString(key.getKeyID()));
            log.println("algorithm: " + key.getAlgorithm());
        }
        encryptor.addMethod(key);
        OutputStream encryptedOut = encryptor.open(bytesOut, data.length);
        encryptedOut.write(data);

        encryptedOut.close();
        encryptor.close();

        encryptedData = bytesOut.toByteArray();
        // openpgp.logPGPData("encrypted", encryptedData);

        return encryptedData;
    }

}


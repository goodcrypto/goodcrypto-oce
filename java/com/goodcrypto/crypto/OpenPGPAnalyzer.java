package com.goodcrypto.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.goodcrypto.io.IgnoredLog;
import com.goodcrypto.io.Indentation;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * OpenPGP analyzer.
 * <p>
 * This code relies heavily on Bouncy Castle Crypto.
 * Many of the parameter and return types are from that package, and BC does most
 * of the hard work. For example, we use BC to analyze packets.
 * BC and GPG use the same keyring format, so BC can access GPG keys and
 * decrypt GPG packets. But PGP's keyring format is different (!!!! check this),
 * which means BC can only analyze unencrypted PGP packets.
 * <p>
 * Lots of code is duplicated because similar clases in BC don't share an interface.
 * E.g. PublicXYZ vs PrivateXyz, and SignatureXyz vs OnePassSignatureXyz.
 * We need a way to combine the logging in getObjectList() and the log methods
 * of OpenPGP.
 * <p>
 * We really need to refactor out the common parts of simlar classes in bc, such
 * as PGPSignatureList and PGPOnePassSignatureList.
 *
 * <p>Copyright 2004-2006 GoodCrypto
 * <br>Last modified: 2007.03.05
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class OpenPGPAnalyzer
     implements BCConstants, Constants
{
    private static Log log = new LogFile();

    private final OpenPGP openpgp;
    private final Indentation logIndent = new Indentation();


    /**
     * Constructor for OpenPGPAnalyzer.
     *
     * @param  openpgp  Open PGP utilities
     */
    public OpenPGPAnalyzer(OpenPGP openpgp)
    {
        this.openpgp = openpgp;
    }


    /**
     * Set the log.
     *
     * @param  log  new log
     */
    public static void setLog(Log log)
    {
        OpenPGPAnalyzer.log = log;
    }


    /*
     * Convert input stream to a list of pgp objects.
     * <p>
     * Sometimes we can't read the whole stream,
     * such as when we get an "unknown object in stream" exception.
     * To allow logging these partial streams we log here instead of
     * in a method that first gets the list and then logs it.
     */
    /**
     *  Gets the object list.
     *
     * @param  in                   pgp packet stream
     * @param  passphrase           passphrase
     * @param  logging              if logging data
     * @return                      object list
     * @exception  CryptoException  Crypto exception
     */
    public List getObjectList(InputStream in, String passphrase, boolean logging)
        throws CryptoException
    {
        List objects = new Vector();

        try {
            PGPObjectFactory pgpFact = getFactory(in, objects, logging);
            Object object = OpenPGP.getFirstObject(pgpFact);

            if (object == null) {
                log.println("no objects in stream");
            }

            boolean done = false;
            while (object != null &&
                !done) {

                objects.add(object);

                if (object instanceof PGPSignatureList) {
                    logIndent.deindent();
                }

                log.println(logIndent.prefix() + className(object));

                if (object instanceof InputStream ||
                    object instanceof PGPEncryptedDataList ||
                    object instanceof PGPCompressedData ||
                    object instanceof PGPLiteralData) {
                    logIndent.indent();
                }

                if (object instanceof PGPCompressedData) {
                    PGPCompressedData compressedData = (PGPCompressedData)object;
                    pgpFact = new PGPObjectFactory(compressedData.getDataStream());
                    // we don't need to call OpenPGP.getFirstObject() here
                    // because we already know this is an openpgp data stream
                }

                else if (object instanceof PGPLiteralData) {
                    addLiteralData(objects, (PGPLiteralData)object, logging);
                }

                else if (object instanceof PGPEncryptedDataList) {

                    addEncryptedData(
                        objects, (PGPEncryptedDataList)object, passphrase, logging);

                    // To avoid errors, we bail out here
                    // Does anything ever follow the encrypted data list?
                    done = true;
                }

                else if (object instanceof PGPSignatureList) {
                    checkSignatureList((PGPSignatureList)object);
                }

                else if (object instanceof PGPOnePassSignatureList) {
                    checkOnePassSignatureList((PGPOnePassSignatureList)object);
                }

                else if (object instanceof PGPPublicKeyRing) {
                    addPublicKeyring(objects, (PGPPublicKeyRing)object, logging);
                }

                else if (object instanceof PGPPublicKey) {
                    logPublicKey((PGPPublicKey)object, logging);
                }

                else if (object instanceof PGPSecretKeyRing) {
                    addSecretKeyring(objects, (PGPSecretKeyRing)object, logging);
                }

                else if (object instanceof PGPSecretKey) {
                    logSecretKey((PGPSecretKey)object, logging);
                }

                if (!done) {
                    object = pgpFact.nextObject();
                }
            }
        }
        catch (IOException ioe) {
            throw new CryptoException(ioe);
        }
        catch (PGPException pgpe) {
            throw new CryptoException(pgpe);
        }
        finally {
            logIndent.setLevel(0);
        }

        return objects;
    }


    /**
     *  Gets the decrypted data list.
     *
     * @param  dataList             encrypted packet list
     * @param  passphrase           passphrase
     * @return                      decrypted data list
     * @exception  CryptoException  Crypto Exception
     */
    public List getDecryptedDataList(PGPEncryptedDataList dataList, String passphrase)
        throws CryptoException
    {
        final boolean Logging = false;
        return getDecryptedDataList(dataList, passphrase, Logging);
    }


    /**
     *  Gets the decrypted data list.
     *
     * @param  dataList             encrypted packet list
     * @param  passphrase           passphrase
     * @param  logging              if logging data
     * @return                      decrypted data list
     * @exception  CryptoException  Crypto Exception
     */
    public List getDecryptedDataList(PGPEncryptedDataList dataList,
                                     String passphrase,
                                     boolean logging)
        throws CryptoException
    {
        Vector objects = new Vector();

        try {
            // log.println("DEBUG: secret key pathname is " + openpgp.getSecretKeyringPathname()); //DEBUG
            Iterator items = dataList.getEncyptedDataObjects();
            while (items.hasNext()) {

                Object nextItem = items.next();
                objects.add(nextItem);

                PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData)nextItem;
                if (passphrase == null) {
                    log.println("No passphrase. Unable to decrypt.");
                    // log.printStackTrace(); //DEBUG
                }
                else {
                    long keyID = encryptedData.getKeyID();
                    log.println("Decrypting packets for key id " + Long.toHexString(keyID));
                    if (LogPassphrases) {
                        log.println("DEBUG ONLY! passphrase: " + passphrase);
                    }
                    // log.printStackTrace(); //DEBUG
                    PGPPrivateKey privateKey = null;
                    try {
                        privateKey = openpgp.getPrivateEncryptionKey(keyID, passphrase);
                    }
                    catch (Exception e) {
                        log.println("Unable to get private key for key id " +
                            Long.toHexString(keyID));
                        log.println("This isn't fatal, since it may be the key " +
                            "for just one of multiple recipients, for example");
                        log.println("Nonfatal error: " + e.toString());
                    }
                    if (privateKey == null) {
                        String errorMsg = "No private key for key id " +
                            Long.toHexString(keyID);
                        log.println(errorMsg);
                        // throw new CryptoException(errorMsg);
                    }
                    else {
                        InputStream dataIn = encryptedData.getDataStream(privateKey, BCProvider);
                        // assert(dataIn != null); log.println("got data stream"); //DEBUG
                        List encryptedList = getObjectList(dataIn, passphrase, logging);

                        Iterator decryptedObjects = encryptedList.iterator();
                        while (decryptedObjects.hasNext()) {
                            Object decryptedObj = decryptedObjects.next();
                            // log.println("decrypted object is " + className(decryptedObj)); //DEBUG
                            if ("byte array".equals(className(decryptedObj))) {
                                log.println("decrypted object as String: " + new String((byte[])decryptedObj));
                            }
                            objects.add(decryptedObj);
                        }
                        dataIn.close();

                        // log.println("got decrypted packets"); //DEBUG
                    }
                }
            }
        }
        catch (CryptoException cpe) {
            // ignore pmd - we want to rethrow CryptoExceptions, and handle others below
            throw cpe;
        }
        catch (Exception e) {
            throw new CryptoException(e);
        }

        return objects;
    }


    /**
     *  Gets the encrypted.
     *
     * @param  data  Description of the Param
     * @return       encrypted
     */
    public boolean isEncrypted(byte[] data)
    {
        return isEncrypted(data, null);
    }


    /**
     *  Gets the encrypted.
     *
     * @param  data        Description of the Param
     * @param  passphrase  Description of the Param
     * @return             encrypted
     */
    public boolean isEncrypted(byte[] data, String passphrase)
    {
        boolean encrypted = false;

        try {
            encrypted = dataHasPacket(data, "PGPEncryptedDataList", passphrase);
        }
        catch (CryptoException ce) {
            IgnoredLog.getLog().print(ce);
        }

        return encrypted;
    }


    /**
     *  Gets the signed.
     *
     * @param  data  Description of the Param
     * @return       signed
     */
    public boolean isSigned(byte[] data)
    {
        return isSigned(data, null);
    }


    /**
     *  Gets the signed.
     *
     * @param  data        Description of the Param
     * @param  passphrase  Description of the Param
     * @return             signed
     */
    public boolean isSigned(byte[] data, String passphrase)
    {
        boolean signed = false;

        try {
            signed = dataHasPacket(data, "PGPSignatureList", passphrase);
        }
        catch (CryptoException ce) {
            IgnoredLog.getLog().print(ce);
        }

        return signed;
    }


    /**
     * Check whether data contains a specified pgp packet.
     * The package name is not required for the classname,
     * but that could mean we match on the same class name in a different package.
     *
     * @param  data                 Data to check
     * @param  passphrase           optional passphrase for decrypted data
     * @param  className            class name
     * @return                      true iff data has specified packet
     * @exception  CryptoException  Description of the Exception
     */
    public boolean dataHasPacket(byte[] data, String className, String passphrase)
        throws CryptoException
    {
        final boolean Logging = true;
        boolean found = false;

        log.println("looking for class: " + className);

        InputStream in = new ByteArrayInputStream(data);
        List objList = getObjectList(in, passphrase, Logging);
        log.println("object list is " + objList);
        Iterator objects = objList.iterator();
        while (objects.hasNext() &&
            !found) {

            Object object = objects.next();

            String objectName = object.getClass().getName();
            log.println("    packet type: " + objectName);
            found = objectName.equals(className) || objectName.endsWith("." + className);

        }

        if (!found) {
            log.println("not found: " + className);
        }

        return found;
    }


    /**
     * Log pgp data.
     *
     * @param  label                label for log
     * @param  data                 PGP data
     * @exception  CryptoException  Crypto exception
     */
    public void logPGPData(String label, byte[] data)
        throws CryptoException
    {
        logPGPData(label, data, null);
    }


    /**
     * Log pgp data.
     *
     * @param  label                label for log
     * @param  data                 PGP data
     * @param  passphrase           passphrase for decryption
     * @exception  CryptoException  Crypto exception
     */
    public void logPGPData(String label, byte[] data, String passphrase)
        throws CryptoException
    {
        log.print(label, data);
        InputStream in = new ByteArrayInputStream(data);
        logPGPStream(label, in, passphrase);
        try {
            in.close();
        }
        catch (IOException ioe) {
            log.print(ioe);
        }
    }


    /**
     * Log pgp input stream.
     * Warning: This method reads the entire stream, so nothing is left to
     * read after calling this method.
     *
     * @param  label                label to appear in log
     * @param  in                   stream to log
     * @exception  CryptoException  any CryptoException thrown
     */
    public void logPGPStream(String label, InputStream in)
        throws CryptoException
    {
        logPGPStream(label, in, null);
    }


    /**
     * Log pgp input stream.
     * Warning: This method reads the entire stream, so nothing is left to
     * read after calling this method.
     *
     * @param  label       label to appear in log
     * @param  in          stream to log
     * @param  passphrase  passphrase for decryption
     */
    public void logPGPStream(String label, InputStream in, String passphrase)
    {
        final boolean Logging = true;

        try {
            log.println(label + ": pgp stream");
            getObjectList(in, passphrase, Logging);
            log.println(label + ": end of pgp stream");
        }
        catch (Exception ex) {
            // errors just in logging aren't serious
            log.print(ex);
        }
    }


    private PGPObjectFactory getFactory(InputStream in, List objects, boolean logging)
        throws IOException
    {
        InputStream decodedIn = PGPUtil.getDecoderStream(in);
        // ignore pmd here - PGPUtil.getDecoderStream() may simply return its arg, so
        // this is significantly more efficient than equals() and just as clear
        if (decodedIn != in) {
            if (logging) {
                log.println(className(decodedIn));
            }
            objects.add(decodedIn);
        }

        return new PGPObjectFactory(decodedIn);
    }


    private void logPGPPublicKey(PGPPublicKey key)
    {
        log.println(logIndent.prefix() +
            "key ID: " + Long.toHexString(key.getKeyID()));
        logIndent.indent();

        Iterator userIDs = key.getUserIDs();
        if (userIDs.hasNext()) {
            log.println(logIndent.prefix() + "user IDs:");
            logIndent.indent();
            while (userIDs.hasNext()) {
                String userID = (String)userIDs.next();
                log.println(logIndent.prefix() + userID);
            }
            logIndent.deindent();
        }
        else {
            log.println(logIndent.prefix() + "no user ID, same as previous key");
        }

        if (key.isEncryptionKey()) {
            log.println(logIndent.prefix() + "intended for encryption");
        }
        else {
            log.println(logIndent.prefix() + "intended for signing");
        }

        Date creation = key.getCreationTime();
        String timestamp = com.goodcrypto.util.Timestamp.toTimestamp(creation);
        log.println(logIndent.prefix() + "created (UTC): " + timestamp);

        logIndent.deindent();
    }


    private void logPGPSecretKey(PGPSecretKey key)
    {
        log.println(logIndent.prefix() +
            "key ID: " + Long.toHexString(key.getKeyID()));
        logIndent.indent();

        Iterator userIDs = key.getUserIDs();
        if (userIDs.hasNext()) {
            log.println(logIndent.prefix() + "user IDs:");
            logIndent.indent();
            while (userIDs.hasNext()) {
                String userID = (String)userIDs.next();
                log.println(logIndent.prefix() + userID);
            }
            logIndent.deindent();
        }
        else {
            log.println(logIndent.prefix() + "no user ID, same as previous key");
        }

        if (key.isSigningKey()) {
            log.println(logIndent.prefix() + "intended for signing");
        }
        else {
            log.println(logIndent.prefix() + "intended for encryption");
        }

        logIndent.deindent();
    }


    private String className(Object object)
    {
        String className = object.getClass().getName();
        if (className.startsWith("[")) {
            className = className.substring(1);
            // ignore pmd here - we know classname is not null, and this is clearer
            if (className.equals("B")) {
                className = "byte";
            }
            // ignore pmd here - using StringBuffer would clutter this code
            className += " array";
        }
        return className;
    }


    private void addLiteralData(List objects,
                                PGPLiteralData literalData,
                                boolean logging)
        throws IOException
    {
        logIndent.indent();

        // if there's a filename, add it to the list
        String filename = literalData.getFileName();
        if (filename.length() > 0) {
            if (logging) {
                log.println(logIndent.prefix() + "filename " + filename);
            }
            objects.add(filename);
        }

        // add the literal data itself
        InputStream literalIn = literalData.getInputStream();
        ByteArrayOutputStream literalBytes = new ByteArrayOutputStream();
        int b = literalIn.read();
        while (b >= 0) {
            literalBytes.write(b);
            b = literalIn.read();
        }
        if (logging) {
            log.println(logIndent.prefix() + "literal");
        }
        objects.add(literalBytes.toByteArray());
        literalIn.close();

        logIndent.deindent();
    }


    private void addEncryptedData(List objects,
                                  PGPEncryptedDataList encryptedDataList,
                                  String passphrase,
                                  boolean logging)
        throws CryptoException
    {
        logIndent.indent();

        List dataList = getDecryptedDataList(encryptedDataList, passphrase, logging);
        Iterator cryptedObjects = dataList.iterator();
        while (cryptedObjects.hasNext()) {
            Object cryptedObj = cryptedObjects.next();
            if (logging) {
                log.println(logIndent.prefix() + className(cryptedObj));
            }
            objects.add(cryptedObj);
        }

        logIndent.deindent();
    }


    private void checkSignatureList(PGPSignatureList sigs)
    {
        PGPPublicKeyRingCollection publicKeyRings =
            openpgp.getPublicKeyRingCollection();

        logIndent.indent();

        for (int i = 0; i < sigs.size(); ++i) {

            PGPSignature sig = sigs.get(i);

            long keyID = sig.getKeyID();
            try {
                PGPPublicKey key = publicKeyRings.getPublicKey(keyID);
                if (key == null) {
                    log.println(logIndent.prefix() +
                        "No public key for signer.  " +
                        "Signed by keyID: " + Long.toHexString(keyID));
                }
                else {
                    Iterator keyUserIDs = key.getUserIDs();
                    while (keyUserIDs.hasNext()) {
                        String id = (String)keyUserIDs.next();
                        log.println(logIndent.prefix() +
                            "signed by " + id);
                    }
                }
            }
            catch (PGPException pgpe) {
                log.println(logIndent.prefix() +
                    "signed by keyID: " + Long.toHexString(keyID));
                log.print(pgpe.toString());
            }

            logIndent.indent();
            log.println(logIndent.prefix() +
                "on " + sig.getCreationTime());
            log.println(logIndent.prefix() +
                "signature type of " + sig.getSignatureType());
            logIndent.deindent();

        }

        logIndent.deindent();
    }


    private void checkOnePassSignatureList(PGPOnePassSignatureList sigs)
    {
        PGPPublicKeyRingCollection publicKeyRings =
            openpgp.getPublicKeyRingCollection();

        logIndent.indent();

        for (int i = 0; i < sigs.size(); ++i) {

            PGPOnePassSignature sig = sigs.get(i);
            long keyID = sig.getKeyID();

            try {
                PGPPublicKey key = publicKeyRings.getPublicKey(keyID);
                if (key == null) {
                    log.println(logIndent.prefix() +
                        "No public key for signer.  " +
                        "Signed by keyID: " + Long.toHexString(keyID));
                }
                else {
                    Iterator keyUserIDs = key.getUserIDs();
                    while (keyUserIDs.hasNext()) {
                        String id = (String)keyUserIDs.next();
                        log.println(logIndent.prefix() +
                            "signed by " + id);
                    }
                }
            }
            catch (PGPException pgpe) {
                log.println(logIndent.prefix() +
                    "signed by keyID: " + Long.toHexString(keyID));
                log.print(pgpe.toString());
            }

            logIndent.indent();
            // log.println(logIndent.prefix() +
            //     "on " + sig.getCreationTime());
            log.println(logIndent.prefix() +
                "signature type of " + sig.getSignatureType());
            logIndent.deindent();

        }

        logIndent.deindent();
    }


    private void addPublicKeyring(List objects,
                                  PGPPublicKeyRing ring,
                                  boolean logging)
    {
        logIndent.indent();

        log.println(logIndent.prefix() +
            "master public key is " +
            Long.toHexString(ring.getPublicKey().getKeyID()));

        Iterator keys = ring.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey key = (PGPPublicKey)keys.next();
            if (logging) {
                logPGPPublicKey(key);
            }
            objects.add(key);
        }

        logIndent.deindent();
    }


    private void addSecretKeyring(List objects,
                                  PGPSecretKeyRing ring,
                                  boolean logging)
    {
        logIndent.indent();

        log.println(logIndent.prefix() +
            "master public key is " +
            Long.toHexString(ring.getPublicKey().getKeyID()));
        log.println(logIndent.prefix() +
            "master secret key is " +
            Long.toHexString(ring.getSecretKey().getKeyID()));

        Iterator keys = ring.getSecretKeys();
        while (keys.hasNext()) {
            PGPSecretKey key = (PGPSecretKey)keys.next();
            if (logging) {
                logPGPSecretKey(key);
            }
            objects.add(key);
        }

        logIndent.deindent();
    }


    private void logPublicKey(PGPPublicKey key, boolean logging)
    {
        logIndent.indent();
        if (logging) {
            logPGPPublicKey(key);
        }
        logIndent.deindent();
    }


    private void logSecretKey(PGPSecretKey key, boolean logging)
    {
        logIndent.indent();
        if (logging) {
            logPGPSecretKey(key);
        }
        logIndent.deindent();
    }
}


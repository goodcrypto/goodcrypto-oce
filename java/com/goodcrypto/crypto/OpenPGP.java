package com.goodcrypto.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

import com.goodcrypto.crypto.key.OpenPGPKeys;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.io.Streamer;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * OpenPGP utilities.
 * These are generic openpgp methods that do not depend on a specific underlying
 * crypto package.
 * <p>
 * This code relies heavily on Bouncy Castle Crypto.
 * Many of the parameter and return types are from that package, and it does most
 * of the hard work. For example, we use BC to analyze packets.
 * <p>
 * Lots of code is duplicated because similar clases in BC don't share an interface.
 * E.g. PublicXYZ vs PrivateXyz, and SignatureXyz vs OnePassSignatureXyz.
 * <p>
 * We'd prefer for as many methods as possible to be static, but some rely on
 * specific keyring files, which are not static.
 * <p>
 * You encrypt with the public key of someone else's keypair.
 * You decrypt with the matching private key.
 * <p>
 * You sign with the private key of your own keypair.
 * You verify a signature with the matching public key.
 * <p>
 * Depending on the type of key, it may be used for encryption, signing, or both.
 * <p>
 * A user id is a string, usually an email address.
 * A key id is an integer.
 * <p>
 * Much of this code would be clearer if it consistently handled streams instead of
 * byte arrays. That's true of the oce code in general.
 * <p>
 * We need to clean up exception handling, particularly when we use "// throws Exception".
 * We also need a better way to handle the checks for PGPCompressedData.
 * There are multiple places where we assume just one signature.
 *
 * <p>Copyright 2004-2005 GoodCrypto
 * <br>Last modified: 2007.03.07
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class OpenPGP
     extends OpenPGPKeys
{
    private static Log log = new LogFile();

    private OpenPGPAnalyzer analyzer;


    /** Constructor for OpenPGP. */
    public OpenPGP()
    {
        super();
        init();
    }


    /**
     * Constructor for OpenPGP using keyring files for the specified plugin.
     *
     * @param  crypto  crypto service
     */
    public OpenPGP(CryptoService crypto)
    {
        super(crypto);
        init();
    }


    /**
     * Constructor for OpenPGP.
     *
     * @param  publicKeyringPathname  public keyring filename
     * @param  secretKeyringPathname  secret keyring filename
     */
    public OpenPGP(String publicKeyringPathname, String secretKeyringPathname)
    {
        super(publicKeyringPathname, secretKeyringPathname);
        init();
    }


    /**
     *  Sets the log.
     *
     * @param  log  new log
     */
    public static void setLog(Log newLog)
    {
        log = newLog;
    }



    /**
     * Get the fingerprint in a printable format.
     * <p>
     *
     * @param  fingerprint  fingerprint
     * @return              formatted fingerprint
     */
    public static String getPrintableFingerprint(String fingerprint)
    {
        StringBuffer printableBuffer = new StringBuffer();
        String printable = "";

        if (fingerprint != null &&
            fingerprint.length() > 0) {

            int index = 0;
            int counter = 1;

            while (index < fingerprint.length()) {
                printableBuffer.append(fingerprint.substring(index, index + 1));
                ++index;

                if (counter < 4) {
                    ++counter;
                }

                else {
                    counter = 1;
                    printableBuffer.append(' ');
                }
            }

            printable = printableBuffer.toString().trim();
            log.println("printable fingerprint: " + printable);
        }

        return printable;
    }


    /**
     *  Get the first object from an openpgp factory.
     *  <p>
     *  In different versions of BC a bad stream has been handled differently.
     *  If there are no openpgp objects in the stream, the first call to
     *  nextObject() may return null, or may throw an IOException.
     *  Both errors are converted here to IllegalArgumentException.
     *
     * @param  objects                       object factory
     * @return                               first object
     * @exception  IllegalArgumentException
     */
    public static Object getFirstObject(PGPObjectFactory objects)
        throws IllegalArgumentException
    {
        Object o;
        // make sure this is an open pgp encrypted data stream
        try {
            o = objects.nextObject();
            if (o == null) {
                throw new IllegalArgumentException("Data probably not encrypted.");
            }
        }
        catch (IOException ioe) {
            log.print(ioe);
            // ignore pmd - Java 1.4 won't accept IllegalArgumentException(String, Throwable)
            throw new IllegalArgumentException("Data probably not encrypted.");
        }
        return o;
    }


    /**
     * Get the log used by this plugin. Subclasses can override this method.
     *
     * @return    The Log value
     */
    public Log getLog()
    {
        return log;
    }


    /**
     *  Gets the analyzer.
     *
     * @return    analyzer
     */
    public OpenPGPAnalyzer getAnalyzer()
    {
        return analyzer;
    }


    /**
     * Convert input stream to a list of pgp objects.
     *
     * Objects in a pgp stream are not always concatenated. They may be nested.
     * This array is a record of all objects encountered. When objects contain others
     * the outer object is listed followed by its contents. The original input
     * stream is not included as an initial object.
     *
     * A PGPLiteralData object is followed by the filename, if any, as a String, then
     * followed by the literal data as an InputStream.
     * <p>
     * Warning: This method reads the entire stream, so nothing is left to
     * read after calling this method.
     *
     * @param  in                   pgp packet input stream
     * @return                      The ObjectList value
     * @exception  CryptoException  crypto exception
     */
    public List getObjectList(InputStream in)
        throws CryptoException
    {
        return getObjectList(in, null);
    }


    /**
     * Convert input stream to a list of pgp objects.
     * <p>
     * Objects in a pgp stream are not always concatenated. They may be nested.
     * This array is a record of all objects encountered. When objects contain others
     * the outer object is listed followed by its contents. The original input
     * stream is not included as an initial object.
     * <p>
     * Encrypted data will be decrypted only if the passphrase is not null and is
     * the recipient's correct passphrase.
     * Don't confuse the recipient's passhrase with one used by a sender for signing.
     * <p>
     * A PGPLiteralData object is followed by the filename, if any, as a String, then
     * followed by the literal data as an InputStream.
     * <p>
     * Warning: This method reads the entire stream, so nothing is left to
     * read after calling this method.
     *
     * @param  in                   pgp packet input stream
     * @param  passphrase           decryption passphrase
     * @return                      The ObjectList value
     * @exception  CryptoException  crypto exception
     */
    public List getObjectList(InputStream in, String passphrase)
        throws CryptoException
    {
        final boolean Logging = false;
        return analyzer.getObjectList(in, passphrase, Logging);
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
        return analyzer.getDecryptedDataList(dataList, passphrase, Logging);
    }


    /**
     *  Checks whether date is ascii armored.
     *
     * @param  data  data
     * @return       whether is ascii armored
     */
    public boolean isAsciiArmored(byte[] data)
    {
        final String PGPArmoredPrefix = "-----BEGIN PGP ";
        // !!!!! this isn't very reliable
        return new String(data).trim().startsWith(PGPArmoredPrefix);
        /*
        boolean is = true;
        int i = 0;
        while (is &&
            i < data.length) {
            byte b = data[i];
            is = isBase64Char(b) || b == '\r' || b == '\n';
            ++ i;
        }
        return is;
        */
    }


    /**
     *  Gets whether clear signed.
     *
     * @param  data  data
     * @return       whether clear signed
     */
    public boolean isClearSigned(byte[] data)
    {
        final String ClearSignedPrefix = "-----BEGIN PGP SIGNED MESSAGE-----";
        final String ClearSignedInfix = "-----BEGIN PGP SIGNATURE-----";
        final String ClearSignedSuffix = "-----END PGP SIGNATURE-----";
        String message = (new String(data)).trim();
        return message.startsWith(ClearSignedPrefix) &&
        // we want to check for ClearSignedInfix within the string, so ignore findbugs
            message.indexOf(ClearSignedInfix) > 0 &&
            message.endsWith(ClearSignedSuffix);
    }


    /**
     *  Gets whether base64.
     *
     * @param  data  data
     * @return       whether is base64
     */
    public boolean isBase64(byte[] data)
    {
        boolean is = true;
        int i = 0;
        while (is &&
            i < data.length) {
            is = isBase64Char(data[i]);
            ++i;
        }
        return is;
    }


    /**
     *  Gets the base64 char.
     *
     * @param  c  character
     * @return    whether is base64 char
     */
    public boolean isBase64Char(char c)
    {
        return isBase64Char((int)c);
    }


    /**
     *  Gets the base64 char.
     *
     * @param  c  character
     * @return    whether is base64 char
     */
    public boolean isBase64Char(int c)
    {
        return ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            (c == '+') ||
            (c == '/') ||
            (c == '='));
    }


    /**
     *  Gets the PGP signature.
     *
     * @param  data                 signed data
     * @return                      PGP signature
     * @exception  CryptoException  crypto exception
     * @exception  PGPException     pgp exception
     * @exception  IOException      io exception
     */
    public PGPSignature getPGPSignature(byte[] data)
        throws CryptoException, PGPException, IOException
    {
        PGPSignature sig = null;
        log.print(data);

        if (isClearSigned(data)) {
            sig = getClearSignedSignature(data);
        }
        else {
            sig = getBinarySignature(data);
        }

        if (sig == null) {
            logError("Could not get signer");
        }

        return sig;
    }


    /**
     * Get signature for clearsigned data.
     *
     * @param  data             Signed data
     * @return                  PGP signature
     * @exception  IOException  io exception
     */
    public PGPSignature getClearSignedSignature(byte[] data)
        throws IOException
    {
        // See org.bouncycastle.openpgp.examples.ClearSignedFileProcessor

        InputStream in = new ByteArrayInputStream(data);
        ArmoredInputStream armoredIn = new ArmoredInputStream(in);

        // read past cleartext chars so we can get to the next pgp object
        int ch = armoredIn.read();
        while (ch >= 0 && armoredIn.isClearText()) {
            ch = armoredIn.read();
        }

        PGPObjectFactory pgpFact = new PGPObjectFactory(armoredIn);
        PGPSignatureList sigList = (PGPSignatureList)OpenPGP.getFirstObject(pgpFact);

        armoredIn.close();
        in.close();

        // !!!!! this assumes just one sig
        return sigList.get(0);
    }


    /**
     * Get signature for binary data.
     *
     * @param  data              Signed data
     * @return                   PGP signature
     * @exception  PGPException  pgp exception
     * @exception  IOException   io exception
     */
    public PGPSignature getBinarySignature(byte[] data)
        throws PGPException, IOException
    {
        // See org.bouncycastle.openpgp.examples.SignedFileProcessor

        InputStream in = new ByteArrayInputStream(data);
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpFact = new PGPObjectFactory(in);
        Object object = OpenPGP.getFirstObject(pgpFact);

        if (object instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData)object;
            pgpFact = new PGPObjectFactory(compressedData.getDataStream());
            object = OpenPGP.getFirstObject(pgpFact);
        }

        if (object instanceof PGPOnePassSignatureList) {
            object = pgpFact.nextObject();
            if (object instanceof PGPLiteralData) {
                log.print("literal data", unwrapLiteral((PGPLiteralData)object));
                object = pgpFact.nextObject();
            }
        }

        in.close();

        PGPSignatureList sigList = (PGPSignatureList)object;
        // !!!!! assumes exactly one signature
        PGPSignature sig = sigList.get(0);

        return sig;
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
        analyzer.logPGPData(label, data);
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
        analyzer.logPGPData(label, data, passphrase);
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
        analyzer.logPGPStream(label, in);
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
        analyzer.logPGPStream(label, in, passphrase);
    }


    /**
     *  Log signatures.
     *
     * @param  sigList  signatures
     */
    public void logSignatures(PGPOnePassSignatureList sigList)
    {
        /*
        PGPPublicKeyRingCollection publicKeyRings = getPublicKeyRingCollection();
        PGPOnePassSignature[] sigs = new PGPOnePassSignature[sigList.size()];
        for (int i = 0; i < sigList.size(); ++i) {
            sigs[i] = sigList.get(i);
            long keyID = sigs[i].getKeyID();
            try {
                PGPPublicKey key = publicKeyRings.getPublicKey(keyID);
                Iterator keyUserIDs = key.getUserIDs();
                while (keyUserIDs.hasNext()) {
                    String id = (String) keyUserIDs.next();
                    log.println("signed by " + id);
                }
            }
            catch (PGPException pgpe) {
                log.println("signed by keyID: " + Long.toHexString(keyID));
                log.print(pgpe);
            }
        }
        */
    }


    /**
     * Unwrap a literal packet.
     *
     * @param  literalData      Literal data packet
     * @return                  Literal data
     * @exception  IOException  IO exception
     */
    public byte[] unwrapLiteral(PGPLiteralData literalData)
        throws IOException
    {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        Streamer.copy(literalData.getInputStream(), bytesOut);
        return bytesOut.toByteArray();
    }


    /**
     * Encapsulate in a literal packet.
     *
     * @param  data                 data to wrap in a literal packet
     * @return                      literal packet
     * @exception  IOException      IO exception
     * @exception  CryptoException  Crypto Exception
     */
    public byte[] wrapLiteral(byte[] data)
        throws IOException, CryptoException
    {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator literalGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalGenerator.open(bytesOut,
            PGPLiteralData.BINARY,
            "",
            data.length,
            new Date());
        literalOut.write(data);

        literalOut.close();
        literalGenerator.close();
        bytesOut.close();

        byte[] literalData = bytesOut.toByteArray();
        logPGPData("literal", literalData);

        /* //DEBUG
        // should the callers be responsible for calling compress()?
        byte[] compressedData = compress(literalData);
        return compressedData;
        */
        return literalData; //DEBUG
    }


    /**
     * Compress data.
     *
     * @param  data                 Data to compress
     * @return                      Compressed data
     * @exception  IOException      IO exception
     * @exception  CryptoException  Crypto Exception
     */
    public byte[] compress(byte[] data)
        throws IOException, CryptoException
    {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator compressedGenerator =
            new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        OutputStream compressedOut = compressedGenerator.open(bytesOut);
        compressedOut.write(data);
        compressedOut.close();
        compressedGenerator.close();

        byte[] compressedData = bytesOut.toByteArray();
        logPGPData("compressed", compressedData);

        return compressedData;
    }


    /**
     * Ascii armor.
     *
     * @param  data             Data to armor
     * @return                  Armored data
     * @exception  IOException  IO exception
     */
    public byte[] armor(byte[] data)
        throws IOException
    {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(bytesOut);
        armoredOut.write(data);
        armoredOut.close();
        return bytesOut.toByteArray();
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
        log.print(ce);
        throw ce;
    }


    /**
     * Remove ascii armor.
     *
     * @param  data             Data to armor
     * @return                  Armored data
     * @exception  IOException  IO exception
     */
    public byte[] unarmor(byte[] data)
        throws IOException
    {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(data);
        ArmoredInputStream armoredIn = new ArmoredInputStream(bytesIn);
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        Streamer.copy(armoredIn, bytesOut);
        armoredIn.close();
        bytesIn.close();
        return bytesOut.toByteArray();
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
        log.print(t);

        // if this is a test, stopProgram() won't actually stop the program
        com.goodcrypto.crypto.FatalError.stopProgram(t);
        throw new CryptoException(t.getMessage());
    }


    private void init()
    {
        analyzer = new OpenPGPAnalyzer(this);
        // we'd rather setLog(getLog()), but that would mean the
        // overridable method 'getLog' is called during object construction
        OpenPGPKeys.setLog(log);
    }
}


package com.goodcrypto.crypto.key;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Random;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import com.goodcrypto.crypto.CryptoException;
import com.goodcrypto.io.IgnoredLog;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.util.SubprogramInteraction;


/**
 * Pretty Good Privacy crypto key plugin.
 * <p>
 * Currently duplicates much code from GPGPlugin. E.g. getFingerprint() is identical except
 * for the command.
 * <p>
 * Warning: Code here should be careful to only allow one instance of PGP at a time.
 * <p>
 * Only supports pgp 2.6.3i, so unable to create keys in batch mode.
 * Can we create a new keyring with BC and import the BC-generated key with "pgp -ka"?
 * How about an ascii armored key instead of a keyring?
 *
 * <p>Copyright 2004 GoodCrypto
 * <br>Last modified: 2007.04.19
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class PGPPlugin
     extends com.goodcrypto.crypto.PGPPlugin
     implements KeyService, Constants, PGPPluginConstants
{

    /** Type to generate key.
     *  Findbugs 1.0rc1 has some bugs with inner classes. 
     */
    class RandomTyper
         extends Thread
    {
        private SubprogramInteraction subprogram;
        private boolean doneTyping = false;


        public void startTyping(SubprogramInteraction subprogram)
        {
            this.subprogram = subprogram;
            super.start();
        }


        public void run()
        {
            final int MaxMillis = 2000; // 2 secs
            Random random = com.goodcrypto.util.Random.getDefaultRandom();
            while (!doneTyping) {
                subprogram.write("x");
                try {
                    sleep(random.nextInt(MaxMillis));
                }
                catch (Exception e) {
                    IgnoredLog.getLog().print(e);
                }
            }
        }


        public void stopTyping()
        {
            doneTyping = true;
        }
    }


    private static Log log = new LogFile();


    /** Creates a new PGPPlugin object. */
    public PGPPlugin()
    {
        log.println("Ready");
    }


    /**
     * Get the plugin's name.
     * (copied from KeyService)
     *
     * <p> ignore pmd - the synchronization is already block level
     *
     * @return    Name of the plugin
     */
    public synchronized String getName()
    {
        return PGPPluginConstants.Name;
    }


    /**
     * Get the version of this plugin's implementation, i.e. the CORBA servant's version.
     * (copied from KeyService)
     *
     * <p> ignore pmd - the synchronization is already block level
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
        // this plugin supports all functions except "create"
        log.println("plugin " + getName() + " calling isFunctionSupported: " + func);
        return !CreateFunction.equals(func);
    }


    /**
     *  Create a new public key pair.
     *
     *  Create a new key and add it to the keyring.
     * (copied from KeyService)
     *
     * @param  userID                                       ID for the new key. This is typically an email address.
     * @param  passphrase                                   Passphrase
     * @exception  com.goodcrypto.crypto.CryptoException  crypto exception
     */
    public void create(String userID, String passphrase)
        throws com.goodcrypto.crypto.CryptoException
    {
        log.println("create: userID: " + userID);
        try {
            if (isValid(userID)) {
                String message = "key already exists: " + userID;
                log.println(message);
                throw new CryptoException(message);
            }
            else {

                String[] command = {PGPCommandName, "+force", "-kg"};
                SubprogramInteraction subprogram =
                    new SubprogramInteraction(command);
                subprogram.start();

                // key size
                subprogram.waitFor(
                    "Choose 1, 2, or 3, or enter desired number of bits: ");
                subprogram.writeLine("3");
                // key id
                subprogram.waitForLine("Enter a user ID for your public key:");
                subprogram.writeLine(userID);
                // passphrase
                subprogram.waitFor("Enter pass phrase: ");
                subprogram.writeLine(passphrase);
                subprogram.waitFor("Enter same pass phrase again: ");
                subprogram.writeLine(passphrase);

                RandomTyper randomTyper = new RandomTyper();
                randomTyper.startTyping(subprogram);
                subprogram.waitForLine("Key generation completed.");
                randomTyper.stopTyping();

                subprogram.close();

                String fingerprint = getFingerprint(userID);
                if (fingerprint == null) {
                    throw new CryptoException("unable to create key for " + userID);
                }
                else {
                    log.println(
                        "fingerprint of " + userID + " after create: " +
                        fingerprint);
                }
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }
        log.println("create: done"); //DEBUG
    }


    /**
     *  Delete a key.
     *
     *  Delete an existing key, or key pair, from the keyring.
     * (copied from KeyService)
     *
     * @param  userID                                       ID for the new key. This is typically an email address.
     * @exception  com.goodcrypto.crypto.CryptoException  crypto exception
     */
    public void delete(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        log.println("delete: userID: " + userID);
        try {
            if (isValid(userID)) {

                while (isValid(userID)) {

                    String email = getEmail(userID);
                    if (email != null) {
                        String[] command =
                            {PGPCommandName, "+batchmode", "-kr", "+force", email};
                        SubprogramInteraction subprogram =
                            new SubprogramInteraction(command);
                        subprogram.start();
                        // verify delete
                        subprogram.waitFor(
                            "Are you sure you want this key removed (y/N)? ");
                        subprogram.writeLine("y");
                        // !!!!! the next 2 questions only appear for secret
                        //       keys, but may not hurt
                        subprogram.waitFor(
                            "Do you also want to remove it from the secret keyring (y/N)? ");
                        subprogram.writeLine("y");
                        subprogram.waitFor(
                            "Are you sure you want this key removed (y/N)? ");
                        subprogram.writeLine("y");
                        subprogram.close();
                    }

                }

            }
            else {
                String message = "key is not valid: " + userID;
                log.println(message);
                throw new CryptoException(message);
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }
        log.println("delete: done"); //DEBUG
    }


    /**
     *  Import a public key.
     *
     *  Add a public key to the keyring.
     *  <p>
     *  Some crypto engines will allow more than one public key to be
     *  imported at one time, but applications should not rely on this.
     *
     * @param  data                                         Public key data.
     * @exception  com.goodcrypto.crypto.CryptoException  crypto exception
     */
    public void importPublic(byte[] data)
        throws com.goodcrypto.crypto.CryptoException
    {
        try {
            File tmpFile = File.createTempFile(this.getClass().getName(), "dat");
            FileOutputStream out = new FileOutputStream(tmpFile);
            try {
                out.write(data);
            }
            finally {
                out.close();
            }

            args = new String[]{"-ka", tmpFile.getPath()};

            if (!pgpCommand()) {
                String message = "stderr: " + program.getStderrString();
                log.println(message);
                throw new CryptoException(message);
            }

            tmpFile.delete();
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }
        log.println("importPublic: done"); //DEBUG
    }


    /**
     *  Export a public key.
     *
     *  Export a public key from the keyring.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Public key
     * @exception  com.goodcrypto.crypto.CryptoException  crypto exception
     */
    public String exportPublic(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        String publicKey = null;

        try {
            String email = getEmail(userID);
            if (email != null) {
                args = new String[]{"-kxaf", email};

                if (pgpCommand()) {
                    publicKey = program.getStdoutString();
                }
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        log.println("exportPublic: done"); //DEBUG
        return publicKey;
    }


    /**
     *  Get whether a key ID is valid.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Whether the key ID is valid
     * @exception  com.goodcrypto.crypto.CryptoException  crypto exception
     */
    public boolean isValid(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        return getFingerprint(userID) != null;
    }


    /**
     *   Get a key's fingerprint.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Fingerprint
     * @exception  com.goodcrypto.crypto.CryptoException  crypto exception
     */
    public String getFingerprint(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        final String FingerprintPrefix = "Key fingerprint =";
        String fingerprint = null;

        try {
            String email = getEmail(userID);
            if (email != null) {
                String[] command = {PGPCommandName, "-kvc", email};
                SubprogramInteraction subprogram = 
                    new SubprogramInteraction(command);
                subprogram.start();

                // wait for fingerprint line
                String line = subprogram.readLine();
                while (line != null &&
                    line.indexOf(FingerprintPrefix) < 0) {
                    line = subprogram.readLine();
                }
                // get just the fingerprint, without spaces
                if (line != null) {
                    line = line.substring(line.indexOf(FingerprintPrefix) + FingerprintPrefix.length());
                    line = line.trim();
                    if (line.length() > 0) {
                        fingerprint = line;
                        int spacePosition = fingerprint.indexOf(' ');
                        while (spacePosition >= 0) {
                            // remove the space
                            fingerprint = fingerprint.substring(0, spacePosition) +
                                fingerprint.substring(spacePosition + 1);
                            spacePosition = fingerprint.indexOf(' ');
                        }
                    }
                }

                subprogram.close();
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        log.println("fingerprint for " + userID + ": " + fingerprint);
        return fingerprint;
    }


    private String getEmail(String userID)
    {
        String email = null;
        try {
            email = new InternetAddress(userID).getAddress();
        }
        catch (AddressException ae) {
            log.print(ae);
        }
        return email;
    }
}


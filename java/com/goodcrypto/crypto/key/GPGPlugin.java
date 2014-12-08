package com.goodcrypto.crypto.key;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import com.goodcrypto.crypto.CryptoException;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.util.Subprogram;
import com.goodcrypto.util.SubprogramInteraction;



/**
 * Gnu Privacy Guard crypto key plugin.
 * <p>
 * For the functions that usually insist on /dev/tty, use --batch and specify the key by
 * using the fingerprint, with no spaces.
 * <p>
 * !!!! Warning: Code here should be careful to only allow one instance of gpg at a time.
 *
 * <p>Copyright 2004 GoodCrypto
 * <br>Last modified: 2007.04.25
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class GPGPlugin
     extends com.goodcrypto.crypto.GPGPlugin
     implements KeyService, GPGPluginConstants
{
    private final static String DefaultKeyLength = "1024";
    private final static Log log = new LogFile();
    
    /** Creates a new GPGPlugin object. */
    public GPGPlugin()
    {
        log.println("Ready");
    }


    /**
     * Get the plugin's name.
     * (copied from KeyService)
     *
     * Ignore pmd - this already uses block level synchronization.
     *
     * @return    Name of the plugin
     */
    public synchronized String getName()
    {
        return GPGPluginConstants.Name;
    }


    /**
     * Get the version of this plugin's implementation, i.e. the CORBA servant's version.
     * (copied from KeyService)
     *
     * Ignore pmd - this already uses block level synchronization.
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
        log.println("create: userID: " + userID);
        log.printStackTrace(); //DEBUG
        if (LogPassphrases) {
            log.println("DEBUG ONLY! passphrase: " + passphrase);
        }
        try {
            if (isValid(userID)) {
                String message = "key already exists: " + userID;
                log.println(message);
                throw new CryptoException(message);
            }
            else {
                // get the name and email address from the key ID
                // javamail has no good way to extract a comment from an 
                // address string
                InternetAddress[] addresses = InternetAddress.parse(userID);
                if (addresses.length != 1) {
                    StringBuffer message = new StringBuffer();
                    if (addresses.length < 1) {
                        message.append("No");
                    }
                    else {
                        message.append("More than one");
                    }
                    message.append(" email address found in userID: ");
                    message.append(userID);
                    log.println(message.toString());
                    throw new CryptoException(message.toString());
                }
                InternetAddress address = addresses[0];
                String email = address.getAddress();
                String name = address.getPersonal();
                if (name == null) {
                    name = email;
                }
                // javamail does not extract the comment, but gpg does not 
                // insist on one in batch mode
                // String comment = "gpg key";

                // Generating keys in batch mode with gpg is experimental.
                // See doc/DETAILS in the gpg source directory.
                String command = GpgCommandName + " --no-secmem-warning --batch --gen-key";
                SubprogramInteraction program = new SubprogramInteraction(command);
                try {
                    program.start();
    
                    program.writeLine("Key-Type: DSA");
                    program.writeLine("Key-Length: " + DefaultKeyLength);
                    program.writeLine("Subkey-Type: ELG-E");
                    program.writeLine("Subkey-Length: " + DefaultKeyLength);
                    // never expire
                    program.writeLine("Expire-Date: 0");
                    program.writeLine("Passphrase: " + passphrase);
                    program.writeLine("Name-Real: " + name);
                    // program.writeLine("Name-Comment: " + comment);
                    program.writeLine("Name-Email: " + email);
                    program.writeLine("%commit");
                    program.close();
    
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
                catch (FileNotFoundException fnfe) {
                    throw new CryptoException(fnfe);
                }
                catch (IOException ioe) {
                    throw new CryptoException(ioe);
                }

            }
        }
        catch (AddressException ae) {
            handleUnexpectedException(ae);
        }
        
        log.println("create: done"); //DEBUG
    }


    /**
     *          Delete a key.
     *
     *  Delete an existing key, or key pair, from the keyring.
     * (copied from KeyService)
     *
     * <p>
     * GPG (as of 1.2.3) has a bug that allows more than ine unrelated key to
     * have the same user id.
     * If there is more than one key that matches the user id, all will be deleted.
     *
     * @param  userID                                       ID for the new key. This is typically an email address.
     * @exception  CryptoException  crypto exception 
     */
    public void delete(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        log.println("delete: userID: " + userID);
        try {
            if (isValid(userID)) {
                
                while (isValid(userID)) {

                    String fingerprint = getFingerprint(userID);
                    setArgs(new String[]{
                        "--batch", "--delete-secret-and-public-key", fingerprint});

                    if (!gpgCommand()) {
                        String message = "stderr: " + subprogram.getStderrString();
                        log.println(message);
                        throw new CryptoException(message);
                    }

                }
                
                if (isValid(userID)) {
                    log.println("deleting additional key for " + userID);
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
     *          Import a public key.
     *
     *  Add a public key to the keyring.
     *  <p>
     *  Some crypto engines will allow more than one public key to be imported at
     *  one time, but applications should not rely on this.
     *  <p>
     *  GPG (as of 1.2.3) has a bug that allows import of a key that matches the user
     *  id of an existing key. GPG then does not handle keys for that user id properly.
     *  This method deletes any existing matching keys.
     *
     * @param  data                                         Public key block.
     * @exception  CryptoException  crypto exception
     */
    public void importPublic(byte[] data)
        throws com.goodcrypto.crypto.CryptoException
    {
        try {
            log.println("importing key:\n" + new String(data));

            // remove any matching keys first
            openpgp.removeMatchingKeys(this, data);

            File tmpFile = File.createTempFile(this.getClass().getName(), "dat");
            FileOutputStream out = new FileOutputStream(tmpFile);
            try {
                out.write(data);
            }
            finally {
                out.close();
            }

            setArgs(new String[]{"--import", tmpFile.getPath()});

            if (!gpgCommand()) {
                String message = "stderr: " + subprogram.getStderrString();
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
            setArgs(new String[]{"--armor", "--export", getUserIDSpec(userID)});

            if (gpgCommand()) {
                publicKey = subprogram.getStdoutString();
                log.println("exporting key:\n" + publicKey);
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        log.println("exportPublic: done"); //DEBUG
        return publicKey;
    }


    /**
     *          Returns whether a key ID is valid.
     *          This just checks for a fingerprint.
     *          There is no check for a public key, or private key, ot both.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Whether the key ID is valid
     * @exception  CryptoException  crypto exception 
     */
    public boolean isValid(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        return getFingerprint(userID) != null;
    }


    /**
     *          Returns a key's fingerprint.
     *
     * @param  userID                                       ID for the key. This is typically an email address.
     * @return                                              Fingerprint
     * @exception  CryptoException  crypto exception 
     */
    public String getFingerprint(String userID)
        throws com.goodcrypto.crypto.CryptoException
    {
        String fingerprint = null;

        try {
            String command = 
                GpgCommandName + " --no-secmem-warning " +
                "--fingerprint " + OpenPGPKeys.quoteUserID(getUserIDSpec(userID));
            SubprogramInteraction program = new SubprogramInteraction(command);
            program.start();

            // wait for fingerprint line
            String line = program.readLine();
            while (line != null && fingerprint == null) {
                fingerprint = getFingerprintFromLine(line);
                line = program.readLine();
            }
            if (fingerprint != null) {
                // remove spaces
                int spacePosition = fingerprint.indexOf(' ');
                while (spacePosition >= 0) {
                    // remove the space
                    fingerprint = fingerprint.substring(0, spacePosition) +
                        fingerprint.substring(spacePosition + 1);
                    spacePosition = fingerprint.indexOf(' ');
                }
            }

            program.close();
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        return fingerprint;
    }
    
    
    private String getFingerprintFromLine(String line)
    {
        final String FingerprintPrefix1 = "Key fingerprint =";
        final String FingerprintPrefix2 = "Schl.-Fingerabdruck =";
        
        String fingerprint = null;
        
        String prefix = FingerprintPrefix1;
        int index = line.indexOf(FingerprintPrefix1);
        if (index < 0) {
            prefix = FingerprintPrefix2;
            index = line.indexOf(FingerprintPrefix2);
        }

        if (index > 0) {        
            int offset = index + prefix.length();
            String suffix = line.substring(offset).trim();
            if (suffix.length() > 0) {
                fingerprint = suffix;
            }
        }
                
        return fingerprint;
    }
}


package com.goodcrypto.crypto;
import java.io.BufferedReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.util.Vector;

import com.denova.runtime.OS;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.util.PicoParser;

import com.goodcrypto.util.Subprogram;


/**
 * PGP plugin.
 * <p>
 * This is only tested with the last open source version of PGP, 2.6.
 * Other versions may or may not work.
 * <p>
 * Disabled by returning false in isAvailable until compatible with pgp 5.
 * This plugin seems to work best with pgp 2.6.3a from debian sarge.
 * <p>
 * At least some versions of pgp can't handle passphrases with spaces,
 * unless the passphrase is entered on the command line.
 * Spaces in standard test passphrases passed to this class are removed.
 * When standard test passphrases are added by hand to pgp, remember to
 * remove the spaces.
 *
 * <p>
 * We pass the passphrase on stdin, but we've seen some unreliability
 * with that. See pgpCommandWithPassphrase().
 *
 * <p>!!!!! Enclose public method bodies in try/catch as in GPGPlugin.
 *
 * <p>Copyright 2004-2005 GoodCrypto
 * <br>Last modified: 2007.03.25
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class PGPPlugin
     extends AbstractPlugin
     implements Constants
{
    protected final static String PGPCommandName = "pgp";

    private final static String GoodSignaturePrefix = "Good signature from user ";
    private final static String UseStdio = "-f";
    private final static String DoubleQuote = "\"";
    private final static String Dot = ".";

    /** Empty String array. */
    private final static String[] EmptyStringArray = {};

    /** No standard args for now. */
    private final static String[] StandardArgs = EmptyStringArray;

    private String executablePathname = PGPCommandName;

    protected String[] args = EmptyStringArray;
    protected Subprogram program;

    private static Log log = new LogFile();
    private static String pgpHome = null;
    private int resultCode;
    private String signer;


    /** Constructor for PGPPlugin. */
    public PGPPlugin()
    {
        log.println("Ready");
    }
    
    
    /**
     *  Set executable pathname.
     *
     * @param  pathname executable pathname
     */
    public void setExecutable(String pathname) 
    {
        executablePathname = pathname;
    }

    /**
     *  Get executable pathname.
     *
     * @return executable pathname
     */
    public String getExecutable() 
    {
        return executablePathname;
    }

    /**
     *  Get default executable pathname.
     *
     * @return default executable pathname
     */
    public String getDefaultExecutable() 
    {
        return PGPCommandName;
    }


    /**
     * Remove embedded spaces from test passphrases for pgp.
     * This is mostly for debugging.
     *
     * @param  passphrase  passphrase
     * @return             fixed passphrase
     */
    public static String fixPassphrase(String passphrase)
    {
        final String TestPassphrase =
            com.goodcrypto.crypto.test.Constants.TestPassphrase;
        final String TestPassphrase2 =
            com.goodcrypto.crypto.test.Constants.TestPassphrase2;

        String fixedPassphrase;

        // for test passphrases, work around pgp bug
        // about spaces in passphrases
        if (passphrase.equals(TestPassphrase)) {
            fixedPassphrase = "256AVAudio";
            if (LogPassphrases) {
                log.println(
                    "Debug: passphrase changed" +
                    " from: \"" + passphrase +
                    "\" to: \"" + fixedPassphrase +
                    "\"");
            }
        }
        else if (passphrase.equals(TestPassphrase2)) {
            fixedPassphrase = "MemoryF4800000";
            if (LogPassphrases) {
                log.println(
                    "Debug: passphrase changed" +
                    " from: \"" + passphrase +
                    "\" to: \"" + fixedPassphrase +
                    "\"");
            }
        }
        else {
            fixedPassphrase = passphrase;
        }

        return fixedPassphrase;
    }


    /**
     *  Gets the name.
     *
     * @return    name
     */
    public synchronized String getName()
    {
        return PGPPluginConstants.Name;
    }


    /**
     *  Gets the plugin version.
     *
     * @return    plugin version
     */
    public synchronized String getPluginVersion()
    {
        return "0.1";
    }


    /**
     *  Gets the crypto version.
     *
     * @return                      crypto version
     * @exception  CryptoException  crypto exception
     */
    public synchronized String getCryptoVersion()
        throws CryptoException
    {

        String versionNumber = "";

        args = new String[]{
            };

        if (pgpCommand()) {

            String stderr = program.getStderrString();

            BufferedReader reader = new BufferedReader(new StringReader(stderr));
            try {
                String line = reader.readLine();
                while (line != null &&
                    versionNumber.length() <= 0) {

                    versionNumber = parseVersionNumber(line);
                    line = reader.readLine();

                }
            }
            catch (Exception e) {
                log.print(e);
                throw new CryptoException(e.getMessage());
            }

        }

        log.println("version number is " + versionNumber);
        return versionNumber;
    }


    /**
     * Determine if the crypto app is installed.
     * (copied from KeyService)
     *
     * @return    true if backend app is installed.
     */
    public synchronized boolean isAvailable()
    {
        return false; //DEBUG
        /*DEBUG
        boolean installed = false;
        try {
            // if we can get the version, then the app's installed
            String version = getCryptoVersion();
            if (version != null) {
                version = version.trim();
                if (version.length() > 0) {
                    installed = true;
                }
            }
        }
        catch (CryptoException e) {
            log.println("unable to get version so assume not installed");
        }
        return installed;
        DEBUG*/
    }


    /**
     *  Sign, encrypt, and armor.
     *  To avoid a security bug in openpgp, we should always sign
     *  before we encrypt.
     *
     * @param  data                 data to sign, encrypt, and armor
     * @param  fromUserID           user id to sign with
     * @param  toUserID             user id to encrypt to
     * @param  passphrase           passphrase
     * @return                      signed, encrypted, and armored data
     * @exception  CryptoException  crypto exception
     */
    public synchronized byte[] signEncryptAndArmor(byte[] data, String fromUserID, String toUserID, String passphrase)
        throws CryptoException
    {
        log.println(fromToMessage("encrypting", fromUserID, toUserID) + " and armoring");
        args = new String[]{
            UseStdio,
            "-sea",
            "-u",
            fromUserID,
            toUserID
            };
        return signAndEncrypt(data, fromUserID, toUserID, passphrase, args);
    }


    /**
     *  Sign and encrypt.
     *  To avoid a security bug in openpgp, we should always sign
     *  before we encrypt.
     *
     * @param  data                 data to sign and encrypt
     * @param  fromUserID           user id to sign with
     * @param  toUserID             user id to encrypt to
     * @param  passphrase           passphrase
     * @return                      signed and encrypted data
     * @exception  CryptoException  crypto exception
     */
    public synchronized byte[] signAndEncrypt(byte[] data, String fromUserID, String toUserID, String passphrase)
        throws CryptoException
    {
        log.println(fromToMessage("encrypting", fromUserID, toUserID));
        args = new String[]{
            UseStdio,
            "-se",
            "-u",
            fromUserID,
            toUserID
            };
        return signAndEncrypt(data, fromUserID, toUserID, passphrase, args);
    }


    /**
     *  Encrypt without signing.
     *
     * @param  data                 data to sign and encrypt
     * @param  toUserID             user id to encrypt to
     * @return                      signed and encrypted data
     * @exception  CryptoException  crypto exception
     */
    public synchronized byte[] encryptOnly(byte[] data, String toUserID)
        throws CryptoException
    {
        log.println("encrypting to \"" + toUserID + DoubleQuote);
        args = new String[]{
            UseStdio,
        //DEBUG "-se",
            "-ea",  //DEBUG  we'll probably use MIME later, but for now keep it readable; besides, MIME is unreliable
        toUserID
            };
        if (!pgpCommand(data)) {
            logError("Could not encrypt to \"" + toUserID + DoubleQuote);
        }
        return program.getStdoutByteArray();
    }


    /**
     *  Decrypt.
     *
     * @param  data                 data to decrypt
     * @param  passphrase           passphrase
     * @return                      decrypted data
     * @exception  CryptoException  crypto exception
     */
    public synchronized byte[] decrypt(byte[] data, String passphrase)
        throws CryptoException
    {
        log.println("decrypting");
        if (!pgpCommand(passphrase, data)) {
            logError("Could not decrypt");
        }
        return program.getStdoutByteArray();
    }


    /**
     *  Clearsign. To sign and encrypt, use sign().
     *
     * @param  data                 data to sign and encrypt
     * @param  userID               user id to sign with
     * @param  passphrase           passphrase
     * @return                      signed data
     * @exception  CryptoException  crypto exception
     */
    public synchronized byte[] sign(byte[] data, String userID, String passphrase)
        throws CryptoException
    {
        log.println("signing by " + userID);
        args = new String[]{
            UseStdio,
        //DEBUG "-se",
            "-sa",  //DEBUG  we'll probably use MIME later, but for now keep it readable; besides, MIME is unreliable
        "-u",
            userID
            };
        if (!pgpCommand(passphrase, data)) {
            logError("Could not sign as \"" + userID + DoubleQuote);
        }
        return program.getStdoutByteArray();
    }


    /**
     * Verify data is signed by a specified user id.
     *
     * @param  data                 data to verify
     * @param  byUserID             signer to verify
     * @return                      true if verified
     * @exception  CryptoException  crypto exception
     */
    public synchronized boolean verify(byte[] data, String byUserID)
        throws CryptoException
    {
        log.println("verifying signed by " + byUserID);
        args = new String[]{
            UseStdio
            };
        boolean verified = pgpCommand(data);
        if (verified) {

            signer = getSigner();
            verified = signer.equals(byUserID);
            if (!verified) {
                log.println("Could not verify because signed by \"" + signer + "\", not \"" + byUserID + DoubleQuote);
            }

        }

        else {
            logError("Could not verify");
        }
        return verified;
    }


    /**
     *  Gets the signer.
     *
     * @param  data                 signed data
     * @return                      signer
     * @exception  CryptoException  crypto exception
     */
    public synchronized String getSigner(byte[] data)
        throws CryptoException
    {
        log.println("getting signer");
        args = new String[]{
            UseStdio
            };
        boolean verified = pgpCommand(data);
        if (verified) {
            signer = getSigner();
        }
        else {
            logError("Could not get signer");
        }
        return signer;
    }


    /**
     *         Get list of user IDs.
     *
     * Some crypto engines require an exact match to an existing user ID, no matter
     * what their docs say.
     *
     * @return                      List of user IDs
     * @exception  CryptoException
     */
    public synchronized String[] getUserIDs()
        throws CryptoException
    {
        String[] userIDStrings = null;
        try {

            final String LineSeparatorProperty = "line.separator";
            final String Type = "Type";
            final String Pub = "pub";
            final String Space = " ";

            args = new String[]{
                "-kv"
                };
            if (!pgpCommand()) {
                logError("Could not get user IDs");
            }

            Vector userIDs = new Vector();
            String rawUserIDs = new String(program.getStdoutByteArray());
            String lineEnding = System.getProperty(LineSeparatorProperty);
            PicoParser lines = new PicoParser(rawUserIDs);
            String rawLine = lines.nextToken(lineEnding);
            // skip everything through the "Type..." line
            while (rawLine != null &&
                !rawLine.startsWith(Type)) {
                rawLine = lines.nextToken(lineEnding);
            }
            while (rawLine != null) {

                if (rawLine.startsWith(Space)) {

                    userIDs.add(rawLine.trim());

                }
                else {

                    PicoParser line = new PicoParser(rawLine);

                    String tag = line.nextToken();
                    if (tag != null &&
                        tag.equalsIgnoreCase(Pub)) {

                        // skip the Bits/KeyID
                        line.trim();
                        line.nextToken();

                        // skip the Date
                        line.trim();
                        line.nextToken();

                        userIDs.add(line.trim());

                    }
                }

                rawLine = lines.nextToken(lineEnding);
            }

            log.println("userIDStrings: " + userIDs); //DEBUG
            userIDStrings = (String[]) userIDs.toArray(EmptyStringArray);
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        return userIDStrings;
    }


    /**
     *  Gets the home dir.
     *
     * @return    home dir
     */
    public String getHomeDir()
    {
        if (pgpHome == null) {
            try {
                pgpHome = "";

                if (OS.isWindows()) {
                    pgpHome = "c:\\pgp";
                }

                else {
                    final String UserHomeProperty = "user.home";
                    final String PgpDirname = ".pgp";

                    String userHomePathname = System.getProperty(UserHomeProperty);
                    if (userHomePathname != null) {
                        File pgpDir = new File(userHomePathname, PgpDirname);
                        pgpHome = pgpDir.getPath();
                    }
                }
            }
            catch (Exception e) {
                log.print(e);
            }

            log.println("home dir is " + pgpHome);
        }

        return pgpHome;
    }


    /**
     *  Issue a pgp command.
     *
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean pgpCommand()
        throws CryptoException
    {
        // no passphrase or stdin
        return pgpCommand(null, null);
    }


    /**
     * Issue a pgp command.
     *
     * @param  passphrase           passphrase
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean pgpCommand(String passphrase)
        throws CryptoException
    {
        // no stdin
        return pgpCommand(passphrase, null);
    }


    /**
     *  Issue a pgp command.
     *
     * @param  stdin                data to pass to command on stdin
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean pgpCommand(byte[] stdin)
        throws CryptoException
    {
        // no passphrase
        return pgpCommand(null, stdin);
    }


    /**
     *  Issue a pgp command.
     *
     * @param  passphrase           passphrase
     * @param  stdin                data to pass to command on stdin
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean pgpCommand(String passphrase, byte[] stdin)
        throws CryptoException
    {

        boolean ok = false;

        try {

            String[] command = {executablePathname};

            command = Subprogram.addArgs(command, StandardArgs);
            command = Subprogram.addArgs(command, args);

            if (passphrase == null) {
                log.println("No passphrase");
                program = new Subprogram(command);
                program.start();
            }
            else {
                program = pgpCommandWithPassphrase(command, passphrase);
            }

            if (stdin == null) {
                log.println("No stdin");
            }
            else {
                program.write(stdin);
            }

            resultCode = program.waitFor();
            ok = (resultCode == 0);

        }
        catch (FileNotFoundException fnfe) {
            log.println(fnfe.getMessage());
        }
        catch (Exception e) {
            log.print(e);
            throw new CryptoException(e.getMessage());
        }

        // get ready for the next command
        args = new String[]{};

        log.println("resultCode is " + resultCode);

        return ok;
    }


    /**
     *  Handle an unexpected Exception.
     *
     * @param  t                    Throwable
     * @exception  CryptoException  Crypto exception
     */
    protected void handleUnexpectedException(Throwable t)
        throws CryptoException
    {
        log.print(t);

        // if this is a test, stopProgram() won't actually stop the program
        com.goodcrypto.crypto.FatalError.stopProgram(t);
        throw new CryptoException(t.getMessage());
    }


    private Subprogram pgpCommandWithPassphrase(String[] command,
                                                String passphrase)
       throws CryptoException, FileNotFoundException, IOException
    {
        return pgpCommandWithGoodPassphrase(command, fixPassphrase(passphrase));
    }


    private Subprogram pgpCommandWithGoodPassphrase(String[] command,
                                                    String passphrase)
       throws CryptoException, FileNotFoundException, IOException
    {
        // an actual case where we need enums in java
        // how to send the passphrase
        final int OnCommandLine = 1;
        final int OnStdin = 2;
        final int InEnvironment = 3;
        final int How = OnStdin;

        Subprogram subprogram;

        // at least some versions of pgp can't
        // handle spaces in passphrases
        if (passphrase.indexOf(' ') >= 0) {
            throw new CryptoException(
                "No spaces allowed in pgp passphrases");
        }
        if (LogPassphrases) {
            log.println("DEBUG ONLY! passphrase: " + passphrase);
        }

        if (How == OnCommandLine) {
            String [] fullCommand = Subprogram.addArg(command, "-z");
            fullCommand = Subprogram.addArg(fullCommand, passphrase);
            subprogram = new Subprogram(command);
            subprogram.start();
        }
        else if (How == OnStdin) {
            String[] environment =
                Subprogram.addArg(EmptyStringArray, "PGPPASSFD=0");
            subprogram = new Subprogram(command, environment);
            subprogram.start();
            subprogram.write(passphrase + System.getProperty("line.separator"));
        }
        else if (How == InEnvironment) {
            /*
               PGP (2.6.3ia at least) doesn't accept the passphrase 
               on stdin, file descriptor 0, reliably. 
               But PGP seems to ignore any passphrase in the environment.
            */
            String[] environment =
                Subprogram.addArg(EmptyStringArray, "PGPPASS=" + passphrase);
            subprogram = new Subprogram(command, environment);
            subprogram.start();
        }

        return subprogram;
    }


    /** Ignore pmd - this already uses block level synchronization. */
    private synchronized byte[] signAndEncrypt(byte[] data,
                                               String fromUserID,
                                               String toUserID,
                                               String passphrase,
                                               String[] args)
        throws CryptoException
    {
        log.println(fromToMessage("encrypting", fromUserID, toUserID));
        
        this.args = new String[args.length];
        System.arraycopy(args, 0, this.args, 0, args.length);
        if (!pgpCommand(passphrase, data)) {
            logError(fromToMessage("Could not encrypt", fromUserID, toUserID));
        }
        return program.getStdoutByteArray();
    }


    private String getSigner()
        throws CryptoException
    {

        String stderrString = program.getStderrString();
        BufferedReader reader = new BufferedReader(new StringReader(stderrString));
        try {

            String line = reader.readLine();
            while (line != null &&
                signer == null) {

                if (line.startsWith(GoodSignaturePrefix)) {

                    signer = line.substring(GoodSignaturePrefix.length());

                    // strip trailing dot
                    if (signer.endsWith(Dot)) {
                        signer = signer.substring(0, signer.length() - Dot.length());
                    }

                    // strip quotes
                    if (signer.startsWith(DoubleQuote) &&
                        signer.endsWith(DoubleQuote)) {

                        signer = signer.substring(DoubleQuote.length(), signer.length() - DoubleQuote.length());

                    }
                }

                line = reader.readLine();
            }
        }
        catch (Exception e) {
            log.print(e);
            throw new CryptoException(e.getMessage());
        }

        return signer;
    }


    private String fromToMessage(String message,
                                 String from,
                                 String to)
    {
        return message + " from \"" + from + "\" to \"" + to + DoubleQuote;
    }


    private String parseVersionNumber(String line)
    {

        final String PGPPrefix = "Pretty Good Privacy";
        String versionNumber = "";

        if (line.startsWith(PGPPrefix)) {

            String rawVersion = line.substring(PGPPrefix.length());

            int startIndex = rawVersion.indexOf(' ');
            if (startIndex >= 0) {

                versionNumber = rawVersion.substring(startIndex + 1);

                int endIndex = versionNumber.indexOf(' ');
                if (endIndex >= 0) {

                    versionNumber = versionNumber.substring(0, endIndex);

                }

                // make sure we got something resembling "X.Y"
                int dotIndex = versionNumber.indexOf('.');
                if (dotIndex < 0 ||
                    dotIndex >= versionNumber.length()) {

                    versionNumber = "";

                }
            }
        }

        return versionNumber;
    }


    /** Ignore pmd - this already uses block level synchronization. */
    private synchronized void logError(String message)
        throws CryptoException
    {
        StringBuffer errorMsg = new StringBuffer();
        errorMsg.append("Error: ");
        errorMsg.append(message);
        errorMsg.append(". Result code was ");
        errorMsg.append(resultCode);
        String stderrString = program.getStderrString();
        if (stderrString.length() > 0) {
            errorMsg.append(". Stderr was ");
            errorMsg.append(stderrString);
        }
        log.printStackTrace(errorMsg.toString());
        throw new CryptoException(errorMsg.toString());
    }

}


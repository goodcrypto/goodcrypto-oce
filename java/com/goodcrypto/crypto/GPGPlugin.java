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
import com.goodcrypto.util.SubprogramInteraction;


/**
 * Gnu Privacy Guard crypto plugin.
 * <p>
 * Be careful with how you specify a user ID to GPG.
 * Case insensitive substring matching is the default.
 * For example if you specify the email address "alpha@beta.org" as a user ID,
 * you will match a user ID such as "gamma-alpha@beta.org".
 * You can specify an exact match on the entire user ID by prefixing
 * your user ID spec with "=", e.g. "=John Heinrich <alpha@beta.org>".
 * Another option is to tell GPG you want an exact match on an email
 * address using "<" and ">", e.g. "<alpha@beta.org>".
 * <p>
 * !!!! Warning: Code here should be careful to only allow one instance of gpg at a time.
 * Code may require gpg 1.4.1 or later (e.g. getUserIDs), but does not check for it.
 * <p>
 * Debug note: If there seems to be an extra blank line at the top of decrypted text,
 * check whether we should be using 'subprogram.write(passphrase + "\r")' instead of
 * 'subprogram.write(passphrase + EOL)'.
 *
 * <p>Copyright 2004-2005 GoodCrypto
 * <br>Last modified: 2007.04.19
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class GPGPlugin
     extends AbstractPlugin
     implements Constants, GPGConstants
{
    /** Match email addresses of user IDs. This is the default. 
     *  If a user ID does not include "@", acts like CaseInsensitiveSubstringMatch.
     */
    public static final int EmailMatch = 1;
    /** Match user IDs exactly. */
    public static final int ExactMatch = 2;
    /**
     * Match case insensitive substrings of user IDs.
     *  This is GPG's default, but not the default for this class.
     */
    public static final int CaseInsensitiveSubstringMatch = 3;

    protected final static String GpgCommandName = "gpg";
    private final static String DoubleQuote = "\"";
    private final static String LineSeparatorProperty = "line.separator";
    private final static String EOL = System.getProperty(LineSeparatorProperty);
    private final static String GoodSignaturePrefix = "gpg: Good signature from ";
    
    private static final boolean Debugging = false; 

    private final static String GpgDirname = ".gnupg";
    private final static String UserHomeProperty = "user.home";
    
    private static final long OneMinute = 60000; // one minute, in ms
    private static final long DefaultTimeout = 5 * OneMinute; // 5 min
    
    private String executablePathname = GpgCommandName;

    protected Subprogram subprogram;
    protected int resultCode;

    protected OpenPGP openpgp;

    private static Log log = new LogFile();

    private static String gpgHome = null;

    private static int userIDMatchMethod = EmailMatch;

    private String[] args = {};
    
    private long timeout = DefaultTimeout;


    /** Creates a new GPGPlugin object. */
    public GPGPlugin()
    {
        // make sure gpg has had a chance to create the keyring
        // String version = getCryptoVersion();
        
        if (Debugging) {
            log.println("about to instantiate OpenPGP");
        }
        openpgp = new OpenPGP(this);
        // Ignore pmd - The method getHomeDir() is final, and so is clearLockFiles().
        //              What is pmd griping about?
        clearLockFiles();
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
        return GpgCommandName;
    }



    /**
     *  Get user ID match method.
     *  The default is to match email addresses of user IDs.
     *
     * @return    user ID match method
     */
    public static int getUserIDMatchMethod()
    {
        return userIDMatchMethod;
    }


    /**
     *  Set user ID match method.
     *
     * @param  method  new user ID match method
     */
    public static void setUserIDMatchMethod(int method)
    {
        userIDMatchMethod = method;
    }


    /**
     * Get the version of the underlying crypto.
     * (copied from KeyService)
     *
     * @return                      Crypto version
     * @exception  CryptoException
     */
    public synchronized String getCryptoVersion()
        throws CryptoException
    {
        String versionNumber = null;

        try {
            setArgs(new String[]{"--version"});
            timeout = OneMinute;

            if (gpgCommand()) {
                String version = subprogram.getStdoutString();
                versionNumber = parseVersion(version);
                log.println("version number is " + versionNumber);
            }
        }
        catch (Exception e) {
            log.print(e);
        }
        finally {
            timeout = DefaultTimeout;
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
        return GPGPluginConstants.Name;
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
     * Get signer of data.
     * (copied from KeyService)
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
            setArgs(new String[]{"--verify"});

            boolean verified = gpgCommand(data);

            if (verified) {
                signer = getSigner();
            }
            else {
                logError("Could not get signer");
            }
        }
        catch (CryptoException cpe) {
            // this should have come out of logError, and should be a non-fatal error
            // !!!!! we need a getMessage method here
            throw new CryptoException(cpe.getMessage());
        }
        catch (Exception e) {
            handleUnexpectedException(e);
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
        /** Empty String array used to specify the array type for Vector.toArray(). */
        final String[] EmptyStringArray = {};

        String[] userIDStrings = null;

        try {
            // !!!!! gpg man page says not to use --list-keys because the format is
            //       likely to change.
            //       we need to add the --with-colons flag
            // final String Pub = "pub";
            final String Uid = "uid";
            setArgs(new String[]{"--list-keys"});

            if (!gpgCommand()) {
                logError("Could not get user IDs");
            }

            Vector userIDs = new Vector();
            String rawUserIDs = new String(subprogram.getStdoutByteArray());
            PicoParser lines = new PicoParser(rawUserIDs);
            String rawLine = lines.nextToken(EOL);

            while (rawLine != null) {
                PicoParser line = new PicoParser(rawLine);
                String tag = line.nextToken();

                if (tag != null) {
                    /* this code doesn't appear right, at least for gpg 1.4.1
                    if (tag.equalsIgnoreCase(Pub)) {
                        // skip the Bits/KeyID
                        line.trim();
                        line.nextToken();
                        // skip the Date
                        line.trim();
                        line.nextToken();
                        userIDs.add(line.trim());
                    }
                    else
                    */
                    /* PMD complains that this if could be combined with the outer if,
                       but the code commented out above changes the structure. We 
                       aren't going to combine the ifs until we decide about the code
                       above.
                    */
                    if (tag.equalsIgnoreCase(Uid)) {
                        userIDs.add(line.trim());
                    }
                }

                rawLine = lines.nextToken(EOL);
            }

            if (Debugging) {
                log.println("userIDStrings: " + userIDs);
            }
            userIDStrings = (String[]) userIDs.toArray(EmptyStringArray);
        }
        catch (CryptoException cpe) {
            // this should have come out of logError, and should be a non-fatal error
            // !!!!! we need a getMessage method here
            throw new CryptoException(cpe.getMessage());
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        return userIDStrings;
    }


    /**
     * Determine if the crypto app is installed.
     * (copied from KeyService)
     *
     * @return    true if backend app is installed.
     */
    public synchronized boolean isAvailable()
    {
        boolean installed = false;

        try {
            // if we can get the version, then the app's installed
            String version = getCryptoVersion();
            if (version != null) {

                version = version.trim();
                if (version.length() > 0) {

                    installed = true;

                    try {
                        // create gpg's home directory,
                        // if it doesn't exist already
                        File gpgHomeDir = new File(getHomeDir());
                        if (!gpgHomeDir.exists()) {
                            gpgHomeDir.mkdirs();
                        }
                    }
                    catch (Exception e) {
                        log.print(e);
                    }
                }
            }
        }

        catch (CryptoException e) {

            log.println("unable to get version so assume not installed");
        }

        log.println("GPG's back end app installed: " + installed);

        return installed;
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
        byte[] decryptedData = null;

        try {
            if (Debugging) {
                log.println("decrypting:");
            }
            if (LogPassphrases) {
                log.println("DEBUG ONLY! passphrase: " + passphrase);
            }

            setArgs(new String[]{"--decrypt"});

            if (!gpgCommand(passphrase, data)) {
                logError("Could not decrypt");
            }

            decryptedData = subprogram.getStdoutByteArray();
        }
        catch (CryptoException cpe) {
            // this should have come out of logError, and should be a non-fatal error
            // !!!!! we need a getMessage method here
            throw new CryptoException(cpe.getMessage());
        }
        catch (Exception e) {
            handleUnexpectedException(e);
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
            if (Debugging) {
                log.println("encrypting to \"" + toUserID + DoubleQuote);
                logData(data);
            }
            setArgs(new String[]{
                "--recipient", getUserIDSpec(toUserID),   
                // we'll could use MIME, but for now keep it readable
                "--armor", "--encrypt"
                });

            if (!gpgCommand(data)) {
                logError("Could not encrypt to \"" + toUserID + DoubleQuote);
            }

            encryptedData = subprogram.getStdoutByteArray();
        }
        catch (CryptoException cpe) {
            // this should have come out of logError, and should be a non-fatal error
            // !!!!! we need a getMessage method here
            throw new CryptoException(cpe.getMessage());
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

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
        byte[] signedData = null;

        try {
            setArgs(new String[]{
                "--local-user", getUserIDSpec(userID), "--clearsign"});

            if (!gpgCommand(passphrase, data)) {
                logError("Could not sign as \"" + userID + DoubleQuote);
            }

            signedData = subprogram.getStdoutByteArray();
        }
        catch (CryptoException cpe) {
            // this should have come out of logError, and should be a non-fatal error
            // !!!!! we need a getMessage method here
            throw new CryptoException(cpe.getMessage());
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        logData("signed data", signedData);
        return signedData;
    }


    /**
     * Sign data with the secret key indicated by fromUserID, then encrypt with
     * the public key indicated by toUserID.
     *
     * To avoid a security bug in OpenPGP we must sign before encrypting.
     * (copied from KeyService)
     *
     * @param  data                 Data to encrypt
     * @param  fromUserID           ID indicating which secret key to use. This is typically your own email address.
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
        if (Debugging) {
            log.println("signing by \"" + fromUserID +
                "\" and encrypting to \"" + toUserID + DoubleQuote);
            logData(data);
        }
        setArgs(new String[]{
            "--local-user", getUserIDSpec(fromUserID), 
            "--recipient", getUserIDSpec(toUserID), "--sign",
            "--encrypt"
            });

        return signAndEncrypt(
            data,
            fromUserID,
            toUserID,
            passphrase,
            getArgs());
    }


    /**
     * Sign data with the secret key indicated by fromUserID, then encrypt with
     * the public key indicated by toUserID, then ASCII armor.
     *
     * To avoid a security bug in OpenPGP we must sign before encrypting.
     * (copied from KeyService)
     *
     * @param  data                 Data to encrypt
     * @param  fromUserID           ID indicating which secret key to use. This is typically your own email address.
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
        if (Debugging) {
            log.println("signing by \"" + fromUserID +
                "\" and encrypting to \"" + toUserID +
                "\" and armoring");
            logData(data);
        }
        setArgs(new String[]{
            "--local-user", getUserIDSpec(fromUserID), 
            "--recipient", getUserIDSpec(toUserID), "--armor",
            "--sign", "--encrypt"
            });

        return signAndEncrypt(data,
            fromUserID,
            toUserID,
            passphrase,
            getArgs());
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
        boolean verified;

        try {
            setArgs(new String[]{"--verify"});
            verified = gpgCommand(data);

            if (verified) {
                String signer = getSigner();
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
        catch (CryptoException cpe) {
            // this should have come out of logError, and should be a non-fatal error
            // !!!!! we need a getMessage method here
            throw new CryptoException(cpe.getMessage());
        }
        catch (Exception e) {
            verified = false;
            handleUnexpectedException(e);
        }

        return verified;
    }


    /**
     *  Gets the home dir.
     *  <p>
     *  This method is final because it is called during construction.
     *
     * @return    home dir
     */
    public final synchronized String getHomeDir()
    {
        if (gpgHome == null) {
            try {
                getCryptoVersion();
                if (resultCode == 0) {
                    
                    // reparse the output for the gpg home dir
                    String output = subprogram.getStdoutString();
                    gpgHome = parseGpgHomeDir(output);

                    if (gpgHome == null) {
                        gpgHome = getDefaultHomeDir();
                    }

                    // make sure we use the correct file separator
                    // from 2002 until early 2005, gpg incorrectly
                    // used a forward slash on Windows
                    gpgHome = gpgHome.replace('/', File.separatorChar);
                    gpgHome = gpgHome.replace('\\', File.separatorChar);

                    log.println("home dir is " + gpgHome);
                    
                }
            }
            catch (Exception e) {
                log.print(e);
            }
        }

        return gpgHome;
    }


    /**
     *  Get user ID spec based on userIDMatchMethod.
     *
     * @param  userID  user ID
     * @return         user ID spec
     */
    protected String getUserIDSpec(String userID)
    {
        String idSpec = userID;

        if (userIDMatchMethod == EmailMatch &&
            // if the user ID looks like an email address, use "<" and ">"
            idSpec.indexOf('@') > 0 &&
            idSpec.indexOf('<') < 0 &&
            idSpec.indexOf('>') < 0) {
                
            idSpec = "<" + idSpec + ">";
            
        }
        else if (userIDMatchMethod == ExactMatch &&
                 !idSpec.startsWith("=")) {
                     
            idSpec = "=" + idSpec;
            
        }

        return idSpec;
    }


    /**
     *  Issue a gpg command.
     *
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean gpgCommand()
        throws CryptoException
    {
        // no passphrase or stdin
        return gpgCommand(null, null);
    }


    /**
     *  Issue a gpg command.
     *
     * @param  passphrase           passphrase
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean gpgCommand(String passphrase)
        throws CryptoException
    {
        // no stdin
        return gpgCommand(passphrase, null);
    }


    /**
     *  Issue a gpg command.
     *
     * @param  stdin                data to send to command's stdin
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean gpgCommand(byte[] stdin)
        throws CryptoException
    {
        // no passphrase
        return gpgCommand(null, stdin);
    }


    /**
     *  Issue a gpg command.
     *
     * @param  passphrase           passphrase
     * @param  stdin                data to send to command's stdin
     * @return                      success
     * @exception  CryptoException  crypto exception
     */
    protected boolean gpgCommand(String passphrase,
                                 byte[] stdin)
        throws CryptoException
    {
        final String[] StandardOptions = {
        /** For security, we don't want to use file options. */
            "--no-options",
        /**
         * Gpg complains about mem unless we're root, and we shouldn't be running as root.
         */
            "--no-secmem-warning",
        /**
         * Since different machines have different ideas of what time it is,
         *  we want to ignore time conflicts.
         */
            "--ignore-time-conflict",
        /** "valid-from" is just a different kind of time conflict. */
            "--ignore-valid-from",
        /** We're always in batch mode. */
            "--batch",
        /**  We don't have any trust infrastructure yet. */
            "--always-trust"
            };
        boolean ok = false;

        try {
            // gpg wants [options] <commands> [files]
            String[] command = {executablePathname};
            command = Subprogram.addArgs(command, StandardOptions);

            if (passphrase != null) {
                // passphrase will be passed on stdin, file descriptor 0
                final String[] passphraseOptions = {"--passphrase-fd", "0"};
                command = Subprogram.addArgs(command, passphraseOptions);
            }

            command = Subprogram.addArgs(command, getArgs());
            log.println("command: " + Subprogram.argsToCommandLine(command));

            subprogram = new Subprogram(command);
            subprogram.start();
            if (timeout != 0) {
                subprogram.setTimeout(timeout);
            }

            if (passphrase == null) {
                log.println("WARNING: passphrase is null");
            }
            else if (passphrase.trim().length() <= 0) {
                log.println("WARNING: passphrase is blank");
            }
            else {
                if (LogPassphrases) {
                    log.println("DEBUG ONLY! passphrase: " + passphrase);
                }
                subprogram.write(passphrase + EOL);
            }

            if (stdin != null) {
                subprogram.write(stdin);
            }

            resultCode = subprogram.waitFor();
            ok = (resultCode == 0);

            if (!ok) {
                log.println("result code: " + resultCode);
            }
        }
        catch (FileNotFoundException fnfe) {
            log.println(fnfe.getMessage());
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        // get ready for the next command
        setArgs(new String[]{});

        return ok;
    }


    /**
     *  Handle unexpected exception.
     *
     * @param  t                    unexpected Throwable
     * @exception  CryptoException  crypto exception
     */
    protected void handleUnexpectedException(Throwable t)
        throws CryptoException
    {
        log.print(t);

        // if this is a test, stopProgram() won't actually stop the subprogram
        com.goodcrypto.crypto.FatalError.stopProgram(t);
        throw new CryptoException(t.getMessage());
    }


    /**
     *  Log data.
     *
     * @param  data  data to log
     */
    protected void logData(byte[] data)
    {
        logData("data", data);
    }


    /**
     *  Log data.
     *
     * @param  message  log message
     * @param  data     data to log
     */
    protected void logData(String message, byte[] data)
    {
        log.println(message + ":\n" + new String(data));
    }


    /**
     *  Log error.
     *
     * @param  message              error message
     * @exception  CryptoException  crypto exception
     */
    protected synchronized void logError(String message)
        throws CryptoException
    {
        StringBuffer errorMsg = new StringBuffer();
        errorMsg.append("Error: ");
        errorMsg.append(message);
        errorMsg.append("\nResult code: ");
        errorMsg.append(resultCode);

        String stderrString = subprogram.getStderrString();
        if (stderrString.length() > 0) {
            errorMsg.append(".\nStderr: ");
            errorMsg.append(stderrString);
        }

        log.printStackTrace(errorMsg.toString());
        throw new CryptoException(errorMsg.toString());
    }


    /**
     *  Get args.
     *
     * @return    args
     */
    protected synchronized String[] getArgs()
    {
        return (String[])args.clone();
    }


    /**
     *  Set args.
     *
     * @param  args  new args
     */
    protected synchronized void setArgs(String[] args)
    {
        this.args = new String [args.length];
        System.arraycopy(args, 0, this.args, 0, args.length);
    }


    private String getSigner()
        throws CryptoException
    {
        String signer = null;
        String stderrString = subprogram.getStderrString();
        BufferedReader reader = new BufferedReader(new StringReader(
            stderrString));

        try {
            String line = reader.readLine();

            while (line != null && signer == null) {
                if (line.startsWith(GoodSignaturePrefix)) {
                    signer = line.substring(GoodSignaturePrefix.length());

                    // strip quotes
                    if (signer.startsWith(DoubleQuote) &&
                        signer.endsWith(DoubleQuote)) {
                        signer = signer.substring(DoubleQuote.length(),
                            signer.length() -
                            DoubleQuote.length());
                    }
                }

                line = reader.readLine();
            }
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        return signer;
    }


    /**
     *  Delete gpg lock files.
     *  <p>
     *  Warning: Calling this method when a valid lock file exists can have very
     *  serious consequences.
     *  <p>
     *  What about concurrent gpg usages, particularly by other apps?
     *  <p>
     *  Lock files are in the ~/.gnupg directory and are in the form
     *  ".*.lock", ".?*", or possibly "trustdb.gpg.lock".
     */
    private final void clearLockFiles()
    {
        final String LockFilePrefix1 = ".";
        final String LockFileSuffix1 = ".lock";
        final String LockFilePrefix2 = ".#";
        final String LockFilename3 = "trustdb.gpg.lock";

        if (Debugging) {
            log.println("start clearLockFiles()");
        }
        try {
            if (Debugging) {
                log.println("about to getHomeDir()");
            }
            if (getHomeDir() == null) {
                log.println("unable to get system property " + UserHomeProperty);
            }
            else {

                File gpgDir = new File(getHomeDir());

                // get filenames, including files with leading dots
                // !!!!! we need to generalize and refactor this into a more generic class
                //       to get dir listings

                // File.list() doesn't return files starting with a dot, so
                // this doesn't work:
                //     String[] filenames = gpgDir.list();
                //     if (filenames != null) . . .

                String command;
                String dirName = gpgDir.getPath();

                // add double quotes if there are spaces in the name
                if (dirName.indexOf(' ') != -1) {
                    dirName = "\"" + dirName + "\"";
                }

                if (OS.isWindows()) {
                    command = "cmd.exe /c dir /B " + dirName;
                }
                else {
                    // the first arg is "dash A one", not "dash A el"
                    command = "ls -a1 " + dirName;
                }

                if (Debugging) {
                    log.println("about to start clear program");
                }
                SubprogramInteraction clearProgram = new SubprogramInteraction(command);
                clearProgram.start();
                String[] filenames = new String[0];
                String filename = clearProgram.readLine();
                String lastFilename = null;
                while (filename != null &&
                    !filename.equals(lastFilename)) {
                    if (Debugging) {
                        log.println("filename: " + filename);
                    }
                    filenames = Subprogram.addArg(filenames, filename);
                    lastFilename = filename;
                    filename = clearProgram.readLine();
                }
                if (Debugging) {
                    log.println("about to close clear program");
                }
                clearProgram.close();

                for (int i = 0; i < filenames.length; ++i) {
                    String name = filenames[i];
                    if ((name.startsWith(LockFilePrefix1) && name.endsWith(LockFileSuffix1)) ||
                    // name.startsWith(LockFilePrefix2)) {
                        name.startsWith(LockFilePrefix2) ||
                        name.equals(LockFilename3)) {
                        File file = new File(gpgDir, name);
                        file.delete();
                        log.println("deleted lock file " + name);

                    }
                }
            }
        }

        catch (Exception e) {
            log.print(e);
        }
        if (Debugging) {
            log.println("end clearLockFiles()");
        }
    }


    private String getDefaultHomeDir()
    {
        String defaultHomeDir = "";

        if (OS.isWindows()) {
            defaultHomeDir = "c:\\gnupg";
        }

        else {
            String userHomePathname = System.getProperty(UserHomeProperty);
            if (userHomePathname != null) {
                File gpgDir = new File(userHomePathname, GpgDirname);
                defaultHomeDir = gpgDir.getPath();
            }
        }

        log.println("default home dir is " + defaultHomeDir);

        return defaultHomeDir;
    }


    private String parseGpgHomeDir(String output)
        throws IOException
    {
        String homeDir = null;

        BufferedReader reader = new BufferedReader(new StringReader(output));
        String line = reader.readLine();

        while (line != null &&
            homeDir == null) {

            final String HomeAttribute = "home: ";

            // ignore pmd and findbugs - this string should not be internationalized
            int index = line.toLowerCase().indexOf(HomeAttribute);
            if (index != -1) {

                final String UnixHome = "~/";

                homeDir = line.substring(HomeAttribute.length());

                if (homeDir.startsWith(UnixHome)) {
                    // use the user's home directory to get the full path
                    String userHomePathname = System.getProperty(UserHomeProperty);
                    if (userHomePathname != null) {
                        File gpgDir = new File(userHomePathname, homeDir.substring(UnixHome.length()));
                        homeDir = gpgDir.getPath();
                    }
                }
            }

            // keep looking if we haven't found the home dir, yet
            if (homeDir == null) {
                line = reader.readLine();
            }
        }

        if (homeDir == null) {
            log.println("Warning: home dir not found");
        }

        return homeDir;
    }


    private String parseVersion(String version)
        throws IOException
    {
        String versionNumber = null;

        BufferedReader reader = new BufferedReader(new StringReader(version));
        String line = reader.readLine();

        while (line != null &&
            versionNumber == null) {

            int index = line.lastIndexOf(' ');

            if (index >= 0) {
                String possibleVersionNumber = line.substring(index + 1);

                // make sure we got something resembling "X.Y"
                int dotIndex = possibleVersionNumber.indexOf('.');
                if (dotIndex > 0 &&
                    dotIndex < possibleVersionNumber.length() - 1) {
                    versionNumber = possibleVersionNumber;
                }
                else {
                    log.println("version number not found in " + line);
                }
            }

            // keep looking if we haven't found the version, yet
            if (versionNumber == null) {
                line = reader.readLine();
            }
        }

        if (versionNumber == null) {
            versionNumber = "";
        }

        return versionNumber;
    }


    private synchronized byte[] signAndEncrypt(byte[] data,
                                               String fromUserID,
                                               String toUserID,
                                               String passphrase,
                                               String[] args)
        throws CryptoException
    {
        byte[] encryptedData = null;

        setArgs(args);

        try {
            if (Debugging) {
                logData(data);
            }

            if (!gpgCommand(passphrase, data)) {
                logError("Could not encrypt from \"" + fromUserID +
                    "\" to \"" + toUserID + DoubleQuote);
            }

            encryptedData = subprogram.getStdoutByteArray();
        }
        catch (CryptoException cpe) {
            // ignore pmd - we want to rethrow CryptoExceptions, and handle others below
            throw cpe;
        }
        catch (Exception e) {
            handleUnexpectedException(e);
        }

        return encryptedData;
    }
}


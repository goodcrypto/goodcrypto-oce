package com.goodcrypto.crypto;

/** Public constants for GNU Privacy Guard.
 * <p>Copyright 2004-2005 GoodCrypto
 * <br>Last modified: 2005.09.22
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public interface GPGConstants
{
    /** Name of the GPG service provider. */
    public final static String GPGProvider = "GPG";
    
    /** Directory for GPG keyrings. */
    public final static String GPGDirName = ".gnupg";
    
    /** Filename of GPG public keyring. */
    public final static String GPGPubKeyFilename = "pubring.gpg";
    
    /** Filename of GPG secret keyring. */
    public final static String GPGSecKeyFilename = "secring.gpg";
}

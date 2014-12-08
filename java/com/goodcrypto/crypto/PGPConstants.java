package com.goodcrypto.crypto;

/** Public constants for Pretty Good Privacy.
 * <p>Copyright 2005 GoodCrypto
 * <br>Last modified: 2005.09.22
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public interface PGPConstants
{
    /** Name of the PGP service provider. */
    public final static String PGPProvider = "PGP";
    
    /** Directory for PGP keyrings. */
    public final static String PGPDirName = ".pgp";
    
    /** Filename of PGP public keyring. */
    public final static String PGPPubKeyFilename = "pubring.pgp";
    
    /** Filename of PGP secret keyring. */
    public final static String PGPSecKeyFilename = "secring.pgp";
}

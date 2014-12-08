package com.goodcrypto.crypto;

/**
 * Public constants for Bouncy Castle Crypto.
 * <p>Copyright 2004-2005 GoodCrypto
 * <br>Last modified: 2005.09.22
 * @author GoodCrypto
 * @version 0.1
 */
public interface BCConstants
{
    /** Name of the BC service provider. */
    public final static String BCProvider = "BC";
    
    /** Directory for BC keyrings. */
    public final static String BCDirName = ".bc";
    
    /** Filename of BC public keyring. */
    public final static String BCPubKeyFilename = "pubring.bc";
    
    /** Filename of BC secret keyring. */
    public final static String BCSecKeyFilename = "secring.bc";
}

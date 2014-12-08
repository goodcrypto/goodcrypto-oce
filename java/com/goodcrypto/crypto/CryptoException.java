package com.goodcrypto.crypto;

/**
 * Crypto exception.  
 * <p>Copyright 2003-2004 GoodCrypto
 * <br>2004.10.02
 * 
 * @version 0.1
 * @author GoodCrypto
 */
public final class CryptoException extends Exception
{
    public CryptoException () {
        super ();
    }
    
    public CryptoException (String message) {
        super (message);
    }
    
    public CryptoException (String message, Throwable cause) {
        super (message, cause);
    }
    
    public CryptoException (Throwable cause) {
        super (cause);
    }
}


package com.goodcrypto.crypto;

import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;

import org.bouncycastle.openpgp.PGPException;

/**
 * Pluggable crypto service superclass for the Open Crypto Engine
 * 
 * <p>Copyright 2003-2004 GoodCrypto
 * <br>Last modified: 2007.04.07
 * 
 * @version 0.1
 * @author GoodCrypto
 */
public abstract class AbstractPlugin
     extends AbstractRedirectableCryptoService
{
    private static Log log = new LogFile();
    
    /**
     *  Set executable pathname.
     *  This default implementation does nothing.
     *
     * @param  pathname executable pathname
     */
    public void setExecutable(String pathname) 
    {
        // by default we ignore this, since some plugins don't have an executable
    }

    /**
     *  Get executable pathname.
     *  This default implementation returns null.
     *
     * @return executable pathname
     */
    public String getExecutable() 
    {
        return null;
    }

    /**
     *  Get default executable pathname.
     *  This default implementation returns null.
     *
     * @return default executable pathname
     */
    public String getDefaultExecutable() 
    {
        return null;
    }

    /**
     * Get the log used by this plugin. Subclasses should override this method.
     *
     * @return    The Log value
     */
    protected Log getLog()
    {
        return log;
    }


    /**
     * Handle any unexpected exception.
     * <p>
     * Conventional wisdom says that in a crypto program unexpected exceptions
     * should terminate the program. That doesn't work in the real world.
     * Users are extremely intolerant of program crashes, and should be.
     * We log the exception and rethrow it.
     *
     * @param  t                    Throwable of unexpected exception
     * @exception  CryptoException  Crypto exception
     */
    protected void handleUnexpectedException(Throwable t)
        throws CryptoException
    {
        getLog().print(t);

        if (t instanceof PGPException) {
            Exception e = ((PGPException) t).getUnderlyingException();
            if (e != null) {
                getLog().print("underlying exception:\n");
                handleUnexpectedException(e);
            }
        }

        // if this is a test, stopProgram() won't actually stop the program
        // com.goodcrypto.crypto.FatalError.stopProgram(t);

        throw new CryptoException(t);
    }
}


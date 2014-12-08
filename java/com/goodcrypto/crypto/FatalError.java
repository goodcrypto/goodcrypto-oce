package com.goodcrypto.crypto;

import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;

/**
 * Fatal error proxy.
 *  <p>
 *  This proxy handles fatal errors by calling the default FatalErrorHandler.
 *  <p>
 *  If you want some other response, create your own subclass of FatalErrorHandler
 *  and call <code>setHandler</code> before your program can cause a FatalError.
 *  Pass an instance of your own subclass of FatalErrorHandler to <code>setHandler</code>.
 *  <p>
 *  For example, if your subclass is called TrapFatalError,
 *  <pre>
 *      FatalError.setHandler(new TrapFatalError());
 *  </pre>
 *  <p>
 *  This class and the default FatalErrorHandler need to be refactored out of the crypto package.
 *  <p>
 *  Copyright 2002 GoodCrypto
 *  <br>
 *  Last modified: 2004.04.10
 *
 * @author     GoodCrypto
 * @version    0.1
 * @see        com.goodcrypto.crypto.FatalErrorHandler
 */

public class FatalError
{
    private static Log log = new LogFile();
    private static FatalErrorHandler handler = new FatalErrorHandler();


    // not instantiable
    private FatalError()
    {
    }
    
    
    public static Log getLog() {
        return log;
    }


    public static void stopProgram(Throwable t,
                                   int exitCode)
    {
        handler.stopProgram(t, exitCode);
    }


    public static void stopProgram(Throwable t)
    {
        handler.stopProgram(t);
    }


    public static void stopProgram(String message,
                                   int exitCode)
    {
        handler.stopProgram(message, exitCode);
    }


    public static void stopProgram(String message)
    {
        handler.stopProgram(message);
    }


    public static void stopProgram()
    {
        handler.stopProgram();
    }


    public static void stopProgram(int exitCode)
    {
        handler.stopProgram(exitCode);
    }


    public static void setHandler(FatalErrorHandler handler)
    {
        if (FatalError.handler != handler) {
            String handlerClassname = handler.getClass().getName();
            handler.getLog().println("Set handler to " + handlerClassname + ". This is not an error.");
            handler.getLog().println("See FatalError.log for fatal errors, if any.");
            FatalError.handler = handler;
        }
    }


    public static FatalErrorHandler getHandler()
    {
        return handler;
    }

}


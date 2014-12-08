package com.goodcrypto.crypto;

import com.goodcrypto.io.ExceptionLog;
import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;

/**
 * Fatal error handler.
 *  <p>
 *  This is the default FatalErrorHandler, and the superclass of other handlers.
 *  <p>
 *  In general, any serious error in a crypto program should be fatal.
 *  And a fatal error by definition stops the program, so that's the default.
 *  <p>
 *  If you want some other response, see FatalError and its method <code>setHandler</code>.
 *  <p>
 *  A custom handler only has to override
 *  <code>stopProgram (int exitCode)</code> since the other stopProgram methods
 *  eventually all call it. Overriding <code>getLog ()</code> is also recommended.
 *  If you want error messages to go somewhere other than FatalError.log,
 *  override <code>getFatalErrorLog ()</code>.
 *
 *  <p>Copyright 2002-2006 GoodCrypto
 *  <br>Last modified: 2007.03.03
 *
 * @author     GoodCrypto
 * @version    0.1
 * @see        FatalError
 */

public class FatalErrorHandler
{
    public final static int DefaultErrorCode = 1;
    private final static boolean PrintToStderr = false;

    private static Log log = new LogFile();


    /**
     * Gets the log.
     *
     * @return    log
     */
    public Log getLog()
    {
        return log;
    }


    /**
     * Stop the program.
     *
     * @param  t         Throwable that caused fatal error
     * @param  exitCode  exit code for program
     */
    public void stopProgram(Throwable t,
                            int exitCode)
    {
        printStackTrace(t);
        stopProgram(exitCode);
    }


    /**
     * Stop the program.
     *  Exit code is {@value #DefaultErrorCode}.
     *
     * @param  t  Throwable that caused fatal error
     */
    public void stopProgram(Throwable t)
    {
        printStackTrace(t);
        stopProgram();
    }


    /**
     * Stop the program.
     *
     * @param  message   message to log.
     * @param  exitCode  exit code for program
     */
    public void stopProgram(String message,
                            int exitCode)
    {
        printMessage(message);
        stopProgram(exitCode);
    }


    /**
     *  Stop the program.
     *  Exit code is {@value #DefaultErrorCode}.
     *
     * @param  message  Message to log.
     */
    public void stopProgram(String message)
    {
        printMessage(message);
        stopProgram();
    }


    /**
     *  Stop the program.
     *  Exit code is {@value #DefaultErrorCode}.
     */
    public void stopProgram()
    {
        stopProgram(DefaultErrorCode);
    }


    /**
     * Stop the program.
     *
     * @param  exitCode  exit code for program
     */
    public void stopProgram(int exitCode)
    {
        String message =
            "Unanticipated error. " +
            "Since this is a crypto program, stopping. " +
            "Exit code: " +
            exitCode;
        printMessage(message);
        // Findbugs is unhappy with calling System.exit, 
        // but that is the right thing to do here.
        System.exit(exitCode);
    }


    /**
     * Gets the FatalError log, even if a subclass overides getLog().
     *
     * @return    fatal error log
     */
    private Log getFatalErrorLog()
    {
        return FatalError.getLog();
    }


    private void printStackTrace(Throwable t)
    {
        if (PrintToStderr) {
            t.printStackTrace(System.err);
        }
        ExceptionLog.getLog().print(t);
        getFatalErrorLog().print(t);
        if (getLog() != getFatalErrorLog()) {
            getLog().print(t);
        }
    }


    private void printMessage(String message)
    {
        if (message != null &&
            message.length() > 0) {

            if (PrintToStderr) {
                System.err.println(message);
            }
            getFatalErrorLog().println(message);
            ExceptionLog.getLog().println(message);
            if (getLog() != getFatalErrorLog()) {
                getLog().println(message);
            }

        }
    }

}


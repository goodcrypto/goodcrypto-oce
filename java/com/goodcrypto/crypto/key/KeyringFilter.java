package com.goodcrypto.crypto.key;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.goodcrypto.io.IgnoredLog;
import com.goodcrypto.io.Streamer;


/**
 * OpenPGP keyring filter.
 *
 * <p>Copyright 2004-2006 GoodCrypto
 * <br>Last modified: 2007.03.04
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class KeyringFilter
{
    private final String publicKeyringPathname;
    private final String secretKeyringPathname;

    private InputStream publicIn = null;
    private File publicInFile = null;
    private OutputStream publicOut = null;
    private File publicOutFile = null;
    private InputStream secretIn = null;
    private File secretInFile = null;
    private OutputStream secretOut = null;
    private File secretOutFile = null;

    private boolean opened = false;


    /**
     * Constructor for KeyringFilter.
     *
     * @param  publicKeyringPathname  public keyring pathname
     * @param  secretKeyringPathname  secret keyring pathname
     * @exception  IOException        Description of Exception
     */
    public KeyringFilter(String publicKeyringPathname,
                         String secretKeyringPathname)
        throws IOException
    {
        this.publicKeyringPathname = publicKeyringPathname;
        this.secretKeyringPathname = secretKeyringPathname;
        open();
    }


    /**
     *  Close keyring filter.
     *
     * @exception  IOException  IO Exception
     */
    public void close()
        throws IOException
    {
        if (opened) {

            publicIn.close();
            publicOut.close();
            secretIn.close();
            secretOut.close();

            publicInFile.delete();
            publicOutFile.renameTo(publicInFile);
            secretInFile.delete();
            secretOutFile.renameTo(secretInFile);

            opened = false;

        }
    }


    /**
     *  Copy all existing keyrings from input to output.
     *
     * @exception  IOException  IO Exception
     */
    public void copy()
        throws IOException
    {
        Streamer.copy(publicIn, publicOut);
        Streamer.copy(secretIn, secretOut);
    }


    /**
     *  Get public keyring input stream.
     *
     * @return    public keyring input stream
     */
    public InputStream getPublicIn()
    {
        return publicIn;
    }


    /**
     *  Get public keyring output stream.
     *
     * @return    public keyring output stream
     */
    public OutputStream getPublicOut()
    {
        return publicOut;
    }


    /**
     *  Get secret keyring input stream.
     *
     * @return    secret keyring input stream
     */
    public InputStream getSecretIn()
    {
        return secretIn;
    }


    /**
     *  Get secret keyring output stream.
     *
     * @return    secret keyring output stream
     */
    public OutputStream getSecretOut()
    {
        return secretOut;
    }


    /** {@inheritDoc} */
    protected void finalize()
        throws Throwable
    {
        try {
            close();
        }
        finally {
            super.finalize();
        }
    }


    /**
     *  Open keyring filter.
     *
     * @exception  IOException  IO Exception
     */
    private void open()
        throws IOException
    {
        if (!opened) {

            final String TempSuffix = ".temp";
            String tempPublicKeyringPathname =
                publicKeyringPathname + TempSuffix;
            String tempSecretKeyringPathname =
                secretKeyringPathname + TempSuffix;

            publicInFile = new File(publicKeyringPathname);
            publicOutFile = new File(tempPublicKeyringPathname);

            secretInFile = new File(secretKeyringPathname);
            secretOutFile = new File(tempSecretKeyringPathname);

            publicIn = new FileInputStream(publicInFile);
            publicOut = new FileOutputStream(publicOutFile);

            secretIn = new FileInputStream(secretInFile);
            secretOut = new FileOutputStream(secretOutFile);

            opened = true;

        }
    }

}


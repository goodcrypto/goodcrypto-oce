package com.goodcrypto.crypto.example;

import com.goodcrypto.crypto.CryptoService;
import com.goodcrypto.crypto.CryptoServiceFactory;

/** Crypto client demo.
 *
 *  <p>Copyright 2002-2003 GoodCrypto
 *  <br>Last modified: 2007.03.05
 */
public class CryptoClientDemo {
    
    // This demo uses the Gnu Privacy Guard crypto plugin, but you can use any you like.
    private static final String PluginName = "GPG";
    
    /**
     * Show a plugin's crypto version.
     */
    private void showCryptoVersion (String args[]) {

        try {
            CryptoService ce = CryptoServiceFactory.getService(PluginName, args);
            String version = ce.getCryptoVersion ();
            System.out.println ("crypto version is " + version);
        }
        catch (Exception e) {
            e.printStackTrace ();
        }
    }
    
    /**
     * Start the client
     * @param args Program arguments
     */    
    public static void main (String args[]) {
        CryptoClientDemo demo = new CryptoClientDemo ();
        demo. showCryptoVersion (args);
    }
    
}

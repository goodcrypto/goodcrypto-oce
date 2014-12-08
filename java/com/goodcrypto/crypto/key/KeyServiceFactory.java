package com.goodcrypto.crypto.key;

import java.util.Hashtable;
import java.util.Map;

import com.goodcrypto.crypto.CryptoException;
import com.goodcrypto.crypto.CryptoService;
import com.goodcrypto.crypto.CryptoServiceFactory;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.util.XML;

/**
 * Provides instances of cryptographic services, and other associated access.
 *
 * It may make more sense to make the methods in CryptoServiceFactory
 * non-static and override just the getCryptoPluginClassPrefix and
 * getPluginMap methods. 
 *
 * <p>Copyright 2005 GoodCrypto
 * <br>Last modified: 2007.06.04
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class KeyServiceFactory
     extends CryptoServiceFactory
{
    private final static LogFile log = new LogFile();

    // each plugin should be a singleton
    private static Map keyPlugins = new Hashtable();
    
    private static String savedClassPrefix;
    private static Map savedPlugins;


    /**
     * Get the default instance of a crypto key service.
     *
     * This method actually returns a KeyService.
     * A KeyService is also a CryptoService, but they expose different methods.
     * This return type is CryptoService to match the method in 
     * CryptoServiceFactory.
     *
     * <p>
     * Ignore pmd - this already uses block level synchronization.
     *
     * @return                      instance of default service provider
     * @exception  CryptoException  if there is any crypto exception
     */
    public static synchronized CryptoService getDefaultService()
        throws CryptoException
    {
        setupCryptoService();
        CryptoService service = CryptoServiceFactory.getDefaultService();
        resetCryptoService();
        return service;
    }


    /**
     * Get a crypto service matching the given name.
     * The args, intended primarily for CORBA, are currently ignored.
     *
     * This method actually returns a KeyService. 
     * Its return type specifies CryptoService to match the method in 
     * CryptoServiceFactory. (Why?)
     *
     * @param  serviceProviderName  service provider name
     * @param  args                 arguments, usually for CORBA, currently ignored
     * @return                      instance of crypto service
     * @exception  CryptoException  if there is any crypto exception
     */
    public static CryptoService getService(String serviceProviderName, String args[])
        throws CryptoException
    {
        // this invokes KeyServiceFactory.getService, not CryptoServiceFactory  
        return getService(serviceProviderName);
    }


    /**
     * Get the crypto service matching the given name.
     *
     * This method actually returns a KeyService. 
     * Its return type specifies CryptoService to match the method in 
     * CryptoServiceFactory. (Why?)
     *
     * @param  serviceProviderName  service provider name
     * @return                      instance of crypto service
     * @exception  CryptoException  if there is any crypto exception
     */
    public static CryptoService getService(String serviceProviderName)
        throws CryptoException
    {
        setupCryptoService();
        CryptoService service = 
            CryptoServiceFactory.getService(serviceProviderName);
        resetCryptoService();
        return service;
    }


    /**
     * Get the name for the service provider.
     * <p>
     * This is "GPG", "BC", etc.
     * Generally a plugin's getName() will return a full class name to
     * uniquely identify that plugin. This gets the generic name.
     *
     * @param  service              service provider
     * @return                      name
     * @exception  CryptoException  crypto exception 
     */
    public static String getName(KeyService service)
        throws CryptoException
    {
        String name;
        setupCryptoService();
        try {
            name = getName((CryptoService) service);
        }
        catch (ClassCastException cce) {
            name = service.getName();
        }
        resetCryptoService();
        return name;
    }


    /**
     *  Gets the crypto service matching the given persona from the service provider set.
     *
     * @param  persona              persona
     * @param  serviceProviderSet   crypto service providers, e.g. from options.xml
     * @return                      matching service provider
     * @exception  CryptoException  If there is any crypto exception
     */
    public static CryptoService getPersonaService(XML persona,
                                                  XML serviceProviderSet)
        throws CryptoException
    {
        setupCryptoService();
        CryptoService service = 
            CryptoServiceFactory.getPersonaService(persona, serviceProviderSet);
        resetCryptoService();
        return service;
    }
    
    private static void setupCryptoService()
    {
        final String keyClassSuffix = "key.";
        
        // temporarily change the plugin class prefix
        savedClassPrefix = getCryptoPluginClassPrefix();
        if (!savedClassPrefix.endsWith(keyClassSuffix)) {
            setCryptoPluginClassPrefix(savedClassPrefix + keyClassSuffix);
        }
        
        // temporarily change the plugin map
        savedPlugins = getPluginMap();
        setPluginMap(keyPlugins);
        
        String msg = "Set up key service factory";
        log.println(msg);
        CryptoServiceFactory.getLog().println(msg);
    }
    
    private static void resetCryptoService() 
    {
        // restore original settings
        setCryptoPluginClassPrefix(savedClassPrefix);
        setPluginMap(savedPlugins);
        
        String msg = "Reset key service factory";
        log.println(msg);
        CryptoServiceFactory.getLog().println(msg);
    }
    
}


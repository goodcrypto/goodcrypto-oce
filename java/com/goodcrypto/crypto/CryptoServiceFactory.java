package com.goodcrypto.crypto;

import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import com.goodcrypto.io.Log;
import com.goodcrypto.io.LogFile;
import com.goodcrypto.util.JVM;
import com.goodcrypto.util.Subprogram;
import com.goodcrypto.util.XML;

/*
     WARNING!!!
     If you make any api changes to this class, tell whoever's developing the gui
     so we can adapt the version of com.goodcrypto.crypto.CryptoServiceFactory.java
     in the dir control/test/src.
*/
/**
 * Provides instances of cryptographic services, and other associated access.
 *
 * <p>Copyright 2002-2006 GoodCrypto
 * <br>Last modified: 2007.06.04
 *
 * @author     GoodCrypto
 * @version    0.1
 */
public class CryptoServiceFactory
     implements Constants, XMLTags
{
    /**  Crypto plugin class name prefix. */
    public final static String CryptoPluginClassPrefix = "com.goodcrypto.crypto.";

    /**  Crypto plugin class name suffix. */
    public final static String CryptoPluginClassSuffix = "Plugin";

    /**  Name of default crypto service to use. */
    private final static String DefaultCryptoServiceName = "BC";

    private final static Log log = new LogFile();

    // each plugin should be a singleton
    private static Map plugins = new Hashtable();

    private static String classPrefix = CryptoPluginClassPrefix;


    /**
     * Get the default instance of a crypto service.
     *
     * @return                      instance of default service provider
     * @exception  CryptoException  if there is any crypto exception
     */
    public static CryptoService getDefaultService()
        throws CryptoException
    {
        return getService(getDefaultCryptoServiceName());
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
        // get the plugin name
        String pluginName = persona.getValue(CryptoService);
        if (pluginName == null) {
            log.println("using default plugin: " + getDefaultCryptoServiceName());
            pluginName = getDefaultCryptoServiceName();
        }
        else {
            String userID = persona.getValue(UserID);
            log.println("plugin for persona " + userID + " is " + pluginName);
        }

        // now get the plugin
        CryptoService plugin = getService(pluginName, serviceProviderSet);

        return plugin;
    }


    /**
     * Get a crypto service matching the given name.
     * The args, intended primarily for CORBA, are currently ignored.
     *
     * @param  serviceProviderName  service provider name
     * @param  args                 arguments, usually for CORBA, currently ignored
     * @return                      instance of crypto service
     * @exception  CryptoException  if there is any crypto exception
     */
    public static CryptoService getService(String serviceProviderName, String args[])
        throws CryptoException
    {
        return getService(serviceProviderName);
    }


    /**
     * Get the crypto service matching the given name.
     *
     * @param  serviceProviderName  service provider name
     * @return                      instance of crypto service
     * @exception  CryptoException  if there is any crypto exception
     */
    public static CryptoService getService(String serviceProviderName)
        throws CryptoException
    {
        log.println("service provider name: " + serviceProviderName);
        CryptoService plugin = (CryptoService) getPluginMap().get(serviceProviderName);

        if (plugin == null) {

            String pluginClassName = getClassName(serviceProviderName);
            if (!pluginClassName.equals(serviceProviderName)) {
                log.println("trying alternate service provider name: " + pluginClassName);
                plugin = (CryptoService) getPluginMap().get(pluginClassName);
            }

        }

        if (plugin == null) {
            log.println("not in cache: " + serviceProviderName);

            plugin = getPluginInstance(serviceProviderName);
            getPluginMap().put(serviceProviderName, plugin);
            log.println("added to plugins: " + serviceProviderName);

        }
        else {
            log.println("found in cache: " + serviceProviderName);
        }

        return plugin;
    }


    /**
     * Get the crypto service matching the given name from the specified service provider set.
     *
     * The crypto
     *
     * @param  serviceProviderName  service provider name
     * @param  serviceProviderSet   crypto service providers options
     * @return                      instance of crypto service
     * @exception  CryptoException  if there is any crypto exception
     */
    public static CryptoService getService(String serviceProviderName,
                                           XML serviceProviderSet)
        throws CryptoException
    {
        // each plugin should be a singleton

        // first try whatever we have for the service provider name; it may already be a class
        CryptoService plugin = getService(serviceProviderName);
        if (plugin == null) {

            // see if it's a short name, with the class available in the serviceProviderSet info
            XML pluginOptions = getOptions(serviceProviderName, serviceProviderSet);
            String pluginClassName = pluginOptions.getValue(Class);
            if (pluginClassName != null) {
                plugin = getService(pluginClassName);
            }

        }

        return plugin;
    }


    /**
     * Get the arguments for the service provider matching the given
     * name from the service provider set.
     *
     * @param  serviceProviderName  service provider name
     * @param  serviceProviderSet   crypto service providers, e.g. from options.xml
     * @return                      instance of crypto service
     */
    public static String[] getServiceProviderArgs(String serviceProviderName,
                                                  XML serviceProviderSet)
    {
        final String[] EmptyArgs = {};
        String[] args = EmptyArgs;
        XML pluginOptions = getOptions(serviceProviderName, serviceProviderSet);
        if (pluginOptions != null) {
            String argsString = pluginOptions.getValue(Args);
            if (argsString != null) {
                args = Subprogram.commandLineToArgs(argsString);
            }
        }
        return args;
    }


    /**
     * Get the class name for the named service provider.
     *
     * @param  serviceProviderName  service provider name
     * @return                      class name
     */
    public static String getClassName(String serviceProviderName)
    {
        String newName = serviceProviderName;
        String prefix = getCryptoPluginClassPrefix();
        
        if (!serviceProviderName.startsWith(prefix)) {
            newName = prefix + newName;
            if (!serviceProviderName.endsWith(CryptoPluginClassSuffix)) {
                newName = newName + CryptoPluginClassSuffix;
            }
        }

        return newName;
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
    public static String getName(CryptoService service)
        throws CryptoException
    {
        return getName(service.getName());
    }


    /**
     * Get the short name for the named service provider.
     * <p>
     * This is "GPG", "BC", etc.
     * Generally a plugin's getName() will return a full class name to
     * uniquely identify that plugin. This gets the generic name.
     *
     * @param  serviceProviderName  service provider name
     * @return                      name
     */
    public static String getName(String serviceProviderName)
    {
        String newName;

        if (serviceProviderName.startsWith(getCryptoPluginClassPrefix())) {
            newName = serviceProviderName.substring(
                getCryptoPluginClassPrefix().length());
        }
        else {
            newName = serviceProviderName;
        }

        if (newName.endsWith(CryptoPluginClassSuffix)) {
            int newLength = newName.length() - CryptoPluginClassSuffix.length();
            newName = newName.substring(0, newLength);
        }

        return newName;
    }


    /**
     * Get the default service name.
     *
     * @return    Default service name
     */
    public static String getDefaultCryptoServiceName()
    {
        return DefaultCryptoServiceName;
    }


    /**
     *  Gets the service provider options matching the name from the service provider set.
     *
     * @param  serviceProviderSet   service provider set
     * @param  serviceProviderName  service provider name
     * @return                      matching service provider options
     */
    public static XML getOptions(String serviceProviderName, XML serviceProviderSet)
    {
        XML options = null;

        log.println("looking for service provider options: " + serviceProviderName);
        Iterator xmlPlugins = serviceProviderSet.getChildren().iterator();
        boolean found = false;
        while (xmlPlugins.hasNext() &&
            !found) {

            XML plugin = (XML) xmlPlugins.next();

            if (serviceProviderName.equals(plugin.getValue(com.goodcrypto.crypto.XMLTags.Name))) {

                log.println("plugin options found for: " + serviceProviderName);
                found = true;
                options = plugin;

            }
        }

        return options;
    }


    /**
     *  Get the plugin map.
     *
     *  This maps from a plugin name, such as GPG, to an instance of that plugin.
     *  Each plugin should be a singleton.
     *  <p>
     *  Because this method is overridden in at least one subclass which
     *  needs its method to be public, this method must also be public.
     *
     * @return    The PluginMap value
     */
    public static Map getPluginMap()
    {
        return plugins;
    }


    /**
     * Gets the package prefix for crypto plugin class names.
     * The default is "com.goodcrypto.crypto".
     * A plugin class name consists of this prefix, the
     * service name, and the suffix.
     *
     * @return    package prefix for crypto plugin class names
     */
    protected static String getCryptoPluginClassPrefix()
    {
        return classPrefix;
    }


    /**
     * Sets the package prefix for crypto plugin class names.
     * A plugin class name consists of this prefix, the
     * service name, and the suffix.
     *
     * @param  prefix  package prefix for crypto plugin class names
     */
    protected static void setCryptoPluginClassPrefix(String prefix)
    {
        classPrefix = prefix;
    }


    /**
     *  Get log.
     *
     * @return    The log
     */
    protected static Log getLog()
    {
        return log;
    }


    /**
     *  Set the plugin map.
     *
     * @param  newMap  The new PluginMap value
     */
    protected static void setPluginMap(Map newMap)
    {
        plugins = newMap;
    }


    private static CryptoService getPluginInstance(String pluginClassName)
        throws CryptoException
    {
        CryptoService plugin = null;

        try {
            JVM.logClassLoaders(); //DEBUG
            log.println("about to call forName(" + pluginClassName + ")"); //DEBUG
            plugin = (CryptoService) java.lang.Class.forName(pluginClassName).newInstance();
            log.println("called forName(" + pluginClassName + ")"); //DEBUG
        }
        // ClassNotFoundException, IllegalAccessException, InstantiationException
        catch (Exception e) {

            log.println(
                "did not find class: " + pluginClassName + ": " + 
                e.toString());
            String newPluginClassName = getClassName(pluginClassName);
            if (newPluginClassName.equals(pluginClassName)) {
                log.println("no alternate plugin class name available");
            }
            else {
                log.println(
                    "trying alternate plugin class name: " + 
                    newPluginClassName);
                plugin = getService(newPluginClassName);
            }
            
        }

        if (plugin == null) {
            String msg = "Unable to load plugin class: " + pluginClassName;
            log.println(msg);
            throw new CryptoException(msg);
        }
        else {
            log.println("got plugin class: " + pluginClassName);
        }
        
        return plugin;
    }

}


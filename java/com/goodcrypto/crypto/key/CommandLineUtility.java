package com.goodcrypto.crypto.key;

import java.util.Iterator;

import com.goodcrypto.crypto.CryptoException;
import com.goodcrypto.crypto.CryptoService;
import com.goodcrypto.io.LogFile;

import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Key command line utility program.
 *
 * <p>Copyright 2006 GoodCrypto
 * <br>Last modified: 2007.03.04
 */
public class CommandLineUtility
{
    private final static String ListCommand = "list";
    private final static String CreateCommand = "create";
    private final static String DeleteCommand = "delete";

    private final static LogFile log = new LogFile();

    private final OpenPGPKeys openPGPKeys;
    private final String[] args;
    private final KeyService keyService;


    /**
     * Constructor for CommandLineUtility.
     *
     * @param  args        The command line arguments
     * @param  keyService  crypto key plugin
     */
    public CommandLineUtility(String[] args, KeyService keyService)
    {
        // safer to make a copy
        this.args = new String[args.length];
        System.arraycopy(args, 0, this.args, 0, args.length);

        this.keyService = keyService;
        // a KeyService from KeyServiceFactory is also a CryptoService
        openPGPKeys = new OpenPGPKeys((CryptoService)keyService);
    }


    /**
     *  The main program for the CommandLineUtility class
     *
     * @param  args  The command line arguments
     */
    public static void main(String[] args)
    {
        try {
            final int MinArgs = 2;
            if (args.length >= MinArgs) {

                int argIndex = 0;

                String serviceName = args[argIndex];
                // a CryptoService from KeyServiceFactory is also a KeyService
                KeyService keyService =
                    (KeyService)KeyServiceFactory.getService(serviceName);

                String command = args[++argIndex];

                // make a copy of the remaining args
                ++argIndex;
                int commandArgsLength = args.length - argIndex;
                String[] commandArgs = new String[commandArgsLength];
                System.arraycopy(
                    args, argIndex, commandArgs, 0, commandArgsLength);

                CommandLineUtility commandUtility =
                    new CommandLineUtility(
                    commandArgs, keyService);

                if (command.equals(ListCommand)) {
                    commandUtility.show();
                }

                else if (command.equals(CreateCommand)) {
                    commandUtility.create();
                }

                else if (command.equals(DeleteCommand)) {
                    commandUtility.delete();
                }

                else {
                    System.err.println("unexpected command: " + command);
                    help();
                }
            }
            else {
                help();
            }
        }
        // ignore pmd - we want to catch everything including errors here
        catch (Throwable e) {
            System.err.println(e.getMessage());
            log.print(e);
        }
    }


    private static void help()
    {
        System.err.println("usage: <program name> <key service> <command>");
        System.err.println("    key service:");
        System.err.println("         BC, GPG, etc.");
        System.err.println("    command:");
        System.err.println("        " + ListCommand);
        System.err.println("        " + CreateCommand + " <email address> <passphrase>");
        System.err.println("        " + DeleteCommand + " <email address>");
        // System.err.println("    options:");
    }


    private void show()
    {
        try {
            Iterator keys = openPGPKeys.getPublicKeys();
            while (keys.hasNext()) {
                PGPPublicKey key = (PGPPublicKey)keys.next();

                Iterator keyUserIDs = key.getUserIDs();
                while (keyUserIDs.hasNext()) {
                    String id = (String)keyUserIDs.next();
                    System.out.println(id);
                }

            }
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
            log.print(e);
        }
    }


    private void create()
    {
        int argIndex = 0;
        String keyID = args[argIndex];
        String passphrase = args[++argIndex];
        try {
            keyService.create(keyID, passphrase);
            // System.err.println("created key for " + keyID);
        }
        catch (CryptoException ce) {
            System.err.println(ce.getMessage());
            log.print(ce);
        }
    }


    private void delete()
    {
        int argIndex = 0;
        String keyID = args[argIndex];
        try {
            keyService.delete(keyID);
            // System.err.println("deleted key for " + keyID);
        }
        catch (CryptoException ce) {
            System.err.println(ce.getMessage());
            log.print(ce);
        }
    }
}


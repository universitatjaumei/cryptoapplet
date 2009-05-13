package es.uji.security.ui.applet;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.util.Hashtable;
import java.net.ConnectException;
import java.net.URL;
import java.net.URLConnection;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JOptionPane;

import netscape.javascript.JSException;
import netscape.javascript.JSObject;

import es.uji.security.crypto.SupportedBrowser;
import es.uji.security.crypto.SupportedDataEncoding;
import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.crypto.SupportedSignatureFormat;
import es.uji.security.keystore.IKeyStoreHelper;
import es.uji.security.keystore.clauer.ClauerKeyStore;
import es.uji.security.keystore.dnie.Dnie;
import es.uji.security.keystore.mozilla.Mozilla;
import es.uji.security.keystore.mozilla.MozillaKeyStore;
import es.uji.security.keystore.mscapi.MsCapiKeyStore;
import es.uji.security.keystore.pkcs11.PKCS11KeyStore;
import es.uji.security.ui.applet.io.InputParams;
import es.uji.security.ui.applet.io.OutputParams;
import es.uji.security.util.HexDump;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;

import org.apache.log4j.Logger;

/**
 * Handles all the applet singularities such as applet parameters, applet installation, host
 * navigator and keystore list
 */

public class AppHandler
{
    private Logger log = Logger.getLogger(AppHandler.class);
    
    /* The singleton applet object */
    private static AppHandler singleton;

    /* The Applet or Application Main window who is referencing to */
    private MainWindow _mw = null;

    /* Parent applet reference */
    private SignatureApplet _parent = null;

    // This object interacts with the signature thread and wraps all the multisignature complexity
    public SignatureHandler sigh = null;

    // Testing porpouses only
    private boolean desktopApplicationMode = false;

    // JavaScript Functions 
    private String jsSignOk = "onSignOk";
    private String jsSignError = "onSignError";
    private String jsSignCancel = "onSignCancel";
    private String jsWindowShow = "onWindowShow";

    // Keystores
    public Hashtable<SupportedKeystore, IKeyStoreHelper> keystores = new Hashtable<SupportedKeystore, IKeyStoreHelper>();

    // Signature output format
    private SupportedSignatureFormat signatureFormat = SupportedSignatureFormat.CMS;

    // Input data encoding format
    private SupportedDataEncoding inputDataEncoding = SupportedDataEncoding.PLAIN;
    
    // Host navigator
    private SupportedBrowser navigator = SupportedBrowser.MOZILLA;
    
    // Input/Output Data handling
    private InputParams input;
    private OutputParams output;

    // XAdES signer role customization
    private String[] signerRole;
    private String xadesFilename;
    private String xadesFileMimeType;

    private SSLSocketFactory defaultSocketFactory;

    public AppHandler() throws SignatureAppletException
    {
        this(null);

        desktopApplicationMode = true;
        
        log.debug("Running in desktop application mode");
    }

    /**
     * Base constructor, instantiates an AppHandler object, setting up the target navigator and
     * creating an available keystore mapping.
     * 
     * That class should be used as a Sigleton so you must use getInstance in order to get this
     * class object.
     **/
    
    public AppHandler(SignatureApplet parent) throws SignatureAppletException
    {
        if (parent != null)
        {
            _parent = parent;

            try
            {
                JSObject win = (JSObject) netscape.javascript.JSObject.getWindow(_parent);
                JSObject doc = (JSObject) win.getMember("navigator");
                String userAgent = (String) doc.getMember("userAgent");
    
                if (userAgent != null)
                {
                    userAgent = userAgent.toLowerCase();
    
                    log.debug("Detected user agent " + userAgent);
    
                    if (userAgent.indexOf("explorer") > -1 || userAgent.indexOf("msie") > -1)
                    {
                        this.navigator = SupportedBrowser.IEXPLORER;
                    }
                    else if (userAgent.indexOf("firefox") > -1 || userAgent.indexOf("iceweasel") > -1 || 
                             userAgent.indexOf("seamonkey") > -1 || userAgent.indexOf("gecko") > -1 || 
                             userAgent.indexOf("netscape") > -1)
                    {
                        this.navigator = SupportedBrowser.MOZILLA;
                    }
                }
            }
            catch (JSException exc)
            {
                log.error("Error accesing web browser window", exc);
            }
        }

        log.debug("Navigator variable set to " + this.navigator);
        
        // Keep a copy to restore its value
        defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();

        this.install();
        initKeyStoresTable();
    }

    /**
     * 
     * That method instantiates this Singleton class or returns the Object.
     * 
     * @param parent
     *            the main applet object
     * 
     * @return AppHandler The application handler object.
     **/
    public static AppHandler getInstance(SignatureApplet parent) throws SignatureAppletException
    {
        if (singleton == null)
        {
            singleton = new AppHandler(parent);
        }

        return singleton;
    }

    /**
     * 
     * That method returns the appHandler object, the object must be previously instantiated.
     * 
     * @return AppHandler The application handler object.
     **/
    public static AppHandler getInstance() throws SignatureAppletException
    {
        if (singleton == null)
        {
            singleton = new AppHandler();
        }

        return singleton;
    }

    /**
     * If the browser is not Explorer, this method tries to initialize the spanish dnie if the
     * browser is Internet Explorer, we can rely on cryptoApi to deal with this. Nothing happens if
     * it is not plugged.
     * 
     */
    public void initDnie()
    {
        if (!this.navigator.equals(SupportedBrowser.IEXPLORER))
        {
            try
            {
                // DNI-E stuff
                Dnie dnie = new Dnie();

                /* We let then three password attempts. */
                for (int i = 0; i < 3; i++)
                {
                    if (dnie.isPresent())
                    {
                        // Main window is not yet created
                        PasswordPrompt pp = new PasswordPrompt(null, LabelManager
                                .get("DNIE_PASSWORD_TITLE"), LabelManager.get("DNIE_PIN"));

                        IKeyStoreHelper dnieks = (IKeyStoreHelper) new PKCS11KeyStore(dnie
                                .getDnieConfigInputStream(), null, false);
                        try
                        {
                            if (pp.getPassword() != null)
                            {
                                dnieks.load(pp.getPassword());
                                keystores.put(SupportedKeystore.PKCS11, dnieks);
                            }
                            break;
                        }
                        catch (Exception e)
                        {
                            ByteArrayOutputStream os = new ByteArrayOutputStream();
                            PrintStream ps = new PrintStream(os);
                            e.printStackTrace(ps);
                            String stk = new String(os.toByteArray()).toLowerCase();

                            e.printStackTrace();

                            if (stk.indexOf("incorrect") > -1)
                            {
                                JOptionPane.showMessageDialog(null, LabelManager
                                        .get("ERROR_INCORRECT_DNIE_PWD"), "",
                                        JOptionPane.ERROR_MESSAGE);
                            }
                            else
                            {
                                JOptionPane.showMessageDialog(null, LabelManager
                                        .get("ERROR_UNKNOWN"), "", JOptionPane.ERROR_MESSAGE);
                                break;
                            }
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();

            }
        }
    }

    /**
     * Returns the Application invoker's main window for deal with him.
     * 
     * @return MainWindow The MainWindow application object
     **/
    public MainWindow getMainWindow()
    {
        return _mw;
    }

    /**
     * A method to obtain the selected inputParams depending on the input way (JS exported method)
     * 
     * @return InputParams The inputParam class representing the input method.
     **/
    public InputParams getInputParams()
    {
        return input;
    }

    /**
     * A method to obtain the selected outputParams depending on the output way (JS exported method)
     * 
     * @return OutputParams The outputparam class representing the input method.
     **/
    public OutputParams getOutputParams()
    {
        return output;
    }

    /**
     * A method for getting the selected signer role from setSignerRole JS function.
     * 
     * @return signerRole The selected signerrole for XAdES output format
     **/
    public String[] getSignerRole()
    {
        return signerRole;
    }

    /**
     * A method for getting the selected file name from setXadesFileName JS function.
     * 
     * @return xadesFileName The selected file name for XAdES output format
     **/
    public String getXadesFileName()
    {
        return this.xadesFilename;
    }

    /**
     * A method for getting the selected file Mime Type from setXadesFileName JS function.
     * 
     * @return xadesFileName The selected file Mime Type for XAdES output format
     **/
    public String getXadesFileMimeType()
    {
        return this.xadesFileMimeType;
    }

    /**
     * Returns a string representing the host browser over the applet is running
     * 
     * @return string representing the browser
     **/
    public SupportedBrowser getNavigator()
    {
        return this.navigator;
    }

    /**
     * A method for setting the signer role, that method is called from setSignerRole JS function.
     * 
     *@param signerrole
     *            The signer role to be set for XAdES output format
     */
    public void setSignerRole(String[] signerrole)
    {
        this.signerRole = signerrole;
    }

    /**
     * A method for setting the filename, that method is called from setXadesFileName JS function.
     * 
     *@param filename
     *            The file name to be set for XAdES output format
     */
    public void setXadesFileName(String filename)
    {
        this.xadesFilename = filename;
    }

    /**
     * A method for setting the selected file Mime Type from setXadesFileName JS function.
     * 
     * @param xadesFileName
     *            The selected file Mime Type for XAdES output format
     **/
    public void setXadesFileMimeType(String xadesFileMimeType)
    {
        this.xadesFileMimeType = xadesFileMimeType;
    }

    /**
     * This method sets a reference to the MainWindow's object.
     * 
     * @param mw
     *            MainWindow application object
     */
    public void setMainWindow(MainWindow mw)
    {
        _mw = mw;
    }

    /**
     * Help method for install(), it downloads the dll and writes it down to the filesystem
     * 
     * @param input
     *            URL where get the data from.
     * @param output
     *            Destination path of the dll.
     */
    private void dumpFile(String input, String output) throws IOException
    {
        URL url = new URL(input);
        URLConnection uc = url.openConnection();
        uc.connect();
        InputStream in = uc.getInputStream();

        FileOutputStream fos = new FileOutputStream(output);
        fos.write(OS.inputStreamToByteArray(in));
        fos.close();
        in.close();
    }

    /**
     * Installs the applet on the client, basically downloads and loads MicrosoftCryptoApi dll
     * 
     * @throws SignatureAppletException
     *             with the message
     * @throws
     */
    public void installDll(String downloadUrl, String completeDllPath)
            throws SignatureAppletException
    {
        try
        {
            System.out.println("Doing a dumpfile downloadUrl: " + downloadUrl + "completeDllPath: "
                    + completeDllPath);
            dumpFile(downloadUrl + "MicrosoftCryptoApi_0_3.dll", completeDllPath);
        }
        catch (IOException ioex)
        {
            ioex.printStackTrace();
            throw new SignatureAppletException(LabelManager.get("ERROR_CAPI_DLL_INSTALL"));
        }
    }

    /**
     * Installs the applet on the client, basically downloads and loads MicrosoftCryptoApi dll
     * 
     * @throws SignatureAppletException
     *             with the message
     * @throws
     */
    public void install() throws SignatureAppletException
    {

        if (this.navigator.equals(SupportedBrowser.IEXPLORER))
        {
            String downloadUrl = (_parent.getParameter("downloadUrl") != null) ? _parent
                    .getParameter("downloadUrl") : _parent.getCodeBase().toString();
            String destAbsolutePath = System.getenv("TEMP");

            String completeDllPath = destAbsolutePath + File.separator
                    + "MicrosoftCryptoApi_0_3.dll";
            System.out.println("PATH: " + completeDllPath);
            File dllFile = new File(completeDllPath);

            if (!dllFile.exists())
            {
                installDll(downloadUrl, completeDllPath);
            }
            else
            {
                try
                {
                    byte[] digest = { 0x0e, 0x15, (byte) 0x8d, (byte) 0x9f, 0x6a, (byte) 0xc5,
                            (byte) 0x8b, 0x31, 0x67, 0x30, (byte) 0xbe, (byte) 0x8f, 0x4d, 0x35,
                            0x71, (byte) 0xab, (byte) 0xd4, (byte) 0xc9, (byte) 0xf9, (byte) 0x90 };

                    FileInputStream fis = new FileInputStream(dllFile);

                    MessageDigest dig = MessageDigest.getInstance("SHA1");
                    byte[] readed = new byte[fis.available()];

                    fis.read(readed);
                    dig.update(readed);

                    byte[] origHash = dig.digest();

                    System.out.println(HexDump.xdump(digest));
                    System.out.println("\n---\n");
                    System.out.println(HexDump.xdump(origHash));

                    // Compare it.
                    for (int i = 0; i < origHash.length; i++)
                    {
                        if (origHash[i] != digest[i])
                        {
                            installDll(downloadUrl, completeDllPath);
                            break;
                        }
                    }
                }
                catch (Exception e)
                {
                    throw new SignatureAppletException(e.getMessage(), false);
                }
            }
            try
            {
                // Must check if the dll is already loaded here.
                System.load(completeDllPath);
            }
            catch (Throwable e)
            {
                // We should go on here
                e.printStackTrace();
            }
        }
    }

    /**
     * Returns true if the user has initialized and set a master password for its mozilla
     * certificate store False otherwise
     * 
     * @return true or false indicating the store state
     */
    private boolean isMozillaStoreInitialized()
    {
        try
        {
            MozillaKeyStore mks = new MozillaKeyStore();
            mks.load("".toCharArray());
            mks.cleanUp();
            return true;
        }
        catch (Exception e)
        {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(os);
            e.printStackTrace(ps);
            String stk = new String(os.toByteArray());
            if (stk.indexOf("CKR_USER_TYPE_INVALID") > -1)
                return false;
            return true;
        }
    }

    /**
     * Flushes the KeyStore Hashtable
     * 
     *@throws SignatureAppletException
     **/
    protected void flushKeyStoresTable() throws SignatureAppletException
    {
        keystores.clear();
    }

    /**
     * Initializes the KeyStore Hashtable with the store/s that must be used depending on the
     * navigator
     * 
     *@throws SignatureAppletException
     **/
    protected void initKeyStoresTable() throws SignatureAppletException
    {
        if (this.navigator.equals(SupportedBrowser.IEXPLORER))
        {
            /* Explorer Keystore */
            IKeyStoreHelper explorerks = (IKeyStoreHelper) new MsCapiKeyStore();

            try
            {
                explorerks.load("".toCharArray());
                keystores.put(SupportedKeystore.IEXPLORER, explorerks);
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
                System.out.println("ERR_MS_KEYSTORE_LOAD");
                JOptionPane.showMessageDialog(null, ex.getMessage(), LabelManager
                        .get("ERR_MS_KEYSTORE_LOAD"), JOptionPane.WARNING_MESSAGE);
                // throw new SignatureAppletException(LabelManager.get("ERR_MS_KEYSTORE_LOAD"));
            }
        }
        else
        {
            /* Mozilla Keystore */
            try
            {
                if (isMozillaStoreInitialized())
                {

                    Mozilla mozilla = new Mozilla();

                    IKeyStoreHelper p11mozillaks = (IKeyStoreHelper) new PKCS11KeyStore(mozilla
                            .getPkcs11ConfigInputStream(), mozilla.getPkcs11FilePath(), mozilla
                            .getPkcs11InitArgsString());
                    p11mozillaks.load(null);
                    keystores.put(SupportedKeystore.MOZILLA, p11mozillaks);
                }
                // We have to look here for spanish dnie and ask for the password.

            }
            catch (Exception ex)
            {
                System.out.println("ERR_MOZ_KEYSTORE_LOAD");
                ex.printStackTrace();
                JOptionPane.showMessageDialog(null, ex.getMessage(), LabelManager
                        .get("ERR_MOZ_KEYSTORE_LOAD"), JOptionPane.WARNING_MESSAGE);
                // throw new SignatureAppletException(LabelManager.get("ERR_MOZ_KEYSTORE_LOAD"));
            }

            /* Clauer KeyStore */
            try
            {

                IKeyStoreHelper p11clauerks = (IKeyStoreHelper) new ClauerKeyStore();
                try
                {
                    p11clauerks.load(null);
                    keystores.put(SupportedKeystore.CLAUER, p11clauerks);

                }
                catch (KeyStoreException kex)
                {
                    // Here do nothing because that mean
                    // that there is no clauer plugged on
                    // the system.
                }
                catch (ConnectException cex)
                {
                    // Nothing to do also, clauer is not
                    // installed,go ahead!
                }
            }
            catch (Exception ex)
            {
                JOptionPane.showMessageDialog(null, ex.getMessage(), LabelManager
                        .get("ERR_CL_KEYSTORE_LOAD"), JOptionPane.WARNING_MESSAGE);
                // throw new SignatureAppletException(LabelManager.get("ERR_CL_KEYSTORE_LOAD"));
            }
        }
    }

    /**
     * Returns the IKeyStoreHelper object that represents the store
     * 
     * @param ksName
     *            posible input values are: explorer,mozilla,clauer
     * @return the IkeyStoreHelper object
     */
    public IKeyStoreHelper getKeyStore(SupportedKeystore keystore)
    {
        return this.keystores.get(keystore);
    }

    /**
     * Returns the IKeyStoreHelper object that represents the store
     * 
     * @param ksName
     *            posible input values are: explorer,mozilla,clauer
     * @return the IkeyStoreHelper object
     */
    public Hashtable<SupportedKeystore, IKeyStoreHelper> getKeyStoreTable()
    {
        return this.keystores;
    }

    /**
     * Add a new loaded and authenticated PKCS12 keyStore to the hash table
     */
    public void addP12KeyStore(IKeyStoreHelper pkcs12Store)
    {
        keystores.put(SupportedKeystore.PKCS12, pkcs12Store);
    }

    /**
     * Add a new loaded and authenticated PKCS11 keyStore to the hash table. That function will be
     * implemented in a near future, a Load PKCS#11 entry will appear to the applets main window
     * that will allow to load pkcs#11
     */
    public void addP11KeyStore(IKeyStoreHelper pkcs11Store)
    {
        keystores.put(SupportedKeystore.PKCS11, pkcs11Store);
    }

    /**
     * Calls the javascript function indicated as func with params arguments
     * 
     * @param func
     *            The function that must be invoked
     * @param params
     *            The parameters that must be passed to that function
     */
    public void callJavaScriptCallbackFunction(String func, String[] params)
    {
        if (_parent != null)
        {
            netscape.javascript.JSObject.getWindow(_parent).call(func, params);
        }
        else
        {
            System.out.println("Parent is null called ok");
        }
    }

    /**
     * Select the functions that must be called on signature ok, error and cancel
     * 
     * @param onSignOk
     *            The name of the function to be called on signature ok
     * @param onSignCancel
     *            The name of the function to be called on signature cancel
     * @param onSignError
     *            The name of the function to be called on signature Error
     */
    public void setJavaScriptCallbackFunctions(String onSignOk, String onSignError,
            String onSignCancel, String onWindowShow)
    {
        jsSignOk = onSignOk;
        jsSignError = onSignError;
        jsSignCancel = onSignCancel;
        jsWindowShow = onWindowShow;
    }

    /**
     * Get method for the customized SignCancel method call
     * 
     * @return jsSignCancel The name of the function to be called at DOM
     */
    public String getJsSignCancel()
    {
        return jsSignCancel;
    }

    /**
     * Method that allows to set the signCancel function
     * 
     * @param jsSignCancel
     *            the name of the function to be called on cancel at DOM
     */
    public void setJsSignCancel(String jsSignCancel)
    {
        if (jsSignCancel == null || jsSignCancel.length() == 0)
        {
            throw new IllegalArgumentException("Cancel javascript function can't be null or empty");
        }

        this.jsSignCancel = jsSignCancel;
    }

    /**
     * Get the selected name for signature error function at DOM
     * 
     * @return jsSignError The name of the function
     */
    public String getJsSignError()
    {
        return jsSignError;
    }

    /**
     * Set the name of the function to be called on signature error
     * 
     * @param jsSignError
     *            The name of the error function
     */
    public void setJsSignError(String jsSignError)
    {
        if (jsSignError == null || jsSignError.length() == 0)
        {
            throw new IllegalArgumentException("Error javascript function can't be null or empty");
        }

        this.jsSignError = jsSignError;
    }

    /**
     * Get the selected name for signature ok function at DOM
     * 
     * @return jsSignOk The name of the function
     */
    public String getJsSignOk()
    {
        return jsSignOk;
    }

    /**
     * Get the selected name for signature ok function at DOM
     * 
     * @return jsSignOk The name of the function
     */
    public String getJsWindowShow()
    {
        return jsWindowShow;
    }

    /**
     * Set the Sign ok javascript method to be called on signature ok.
     * 
     * @param jsSignOk
     *            The name of the function
     */
    public void setJsSignOk(String jsSignOk)
    {
        if (jsSignOk == null || jsSignOk.length() == 0)
        {
            throw new IllegalArgumentException("Ok javascript function can't be null or empty");
        }

        this.jsSignOk = jsSignOk;
    }

    /**
     * Get the output format of the signature
     * 
     * @return signatureOutputFormat The name of the output format
     */
    public SupportedSignatureFormat getSignatureFormat()
    {
        return this.signatureFormat;
    }

    /**
     * Sets the output signature format.
     * 
     * @param signOutputFormat
     *            The signature output format description
     */
    public void setSignatureOutputFormat(SupportedSignatureFormat signatureFormat)
    {
        this.signatureFormat = signatureFormat;

        log.debug("Setting signOutputFormat to " + signatureFormat);        
    }

    /**
     * It returns the selected input data encoding
     * 
     * @return inputDataEncoding the selected input data encoding
     */
    public SupportedDataEncoding getInputDataEncoding()
    {
        return this.inputDataEncoding;
    }

    /**
     * A method for get the InputParams class
     * 
     * @return input the InputParams implementation class
     */
    public InputParams getInput()
    {
        return this.input;
    }

    /**
     * A method for setting the encoding type of the input data
     * 
     * @param inputDataEncoding
     *            the encoding name
     */
    public void setInputDataEncoding(SupportedDataEncoding inputDataEncoding)
    {
        this.inputDataEncoding = inputDataEncoding;
        
        log.debug("Setting inputDataEncoding to " + inputDataEncoding);
    }

    /**
     * Sets the InputParams for this signature
     * 
     * @param input
     *            the InputParams implementation class
     */
    public void setInput(InputParams input)
    {
        this.input = input;
    }

    /**
     * Sets the OutputParams for this signature
     * 
     * @param output
     *            the OutputParams implementation class
     */
    public void setOutput(OutputParams output)
    {
        this.output = output;
    }

    /**
     * This method computes the signature, that should be done by a thread
     * 
     */
    public void doSign()
    {
        _mw.getShowSignatureCheckBox().setVisible(false);
        sigh = new SignatureHandler(this);
        sigh.doSign();
    }

    protected SignatureHandler getSignatureHandler()
    {
        return sigh;
    }

    public SignatureApplet getSignatureApplet()
    {
        return _parent;
    }

    /**
     * 
     * This method allow the user to disable the SSL server certificate validation when connecting
     * throughout an https connection
     * 
     * @param b
     */
    public void setSSLCertificateVerfication(boolean validate)
    {

        if (validate)
        {
            HttpsURLConnection.setDefaultSSLSocketFactory(defaultSocketFactory);
        }
        else
        {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
            {
                public java.security.cert.X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }

                public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                        String authType)
                {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                        String authType)
                {
                }
            } };

            // Install the all-trusting trust manager
            try
            {
                SSLContext sc = SSLContext.getInstance("SSL");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            }
            catch (Exception e)
            {
            }
        }
    }
}

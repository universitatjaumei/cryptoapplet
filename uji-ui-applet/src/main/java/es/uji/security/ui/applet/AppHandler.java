package es.uji.security.ui.applet;

import netscape.javascript.JSObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

import es.uji.security.crypto.SupportedBrowser;
import es.uji.security.crypto.SupportedDataEncoding;
import es.uji.security.crypto.SupportedSignatureFormat;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.OS;
import es.uji.security.ui.applet.io.InputParams;
import es.uji.security.ui.applet.io.OutputParams;
import es.uji.security.util.HexDump;
import es.uji.security.util.i18n.LabelManager;

/**
 * Handles all the applet singularities such as applet parameters, applet installation, host
 * navigator and keystore list
 */

public class AppHandler
{
    private static Logger log = Logger.getLogger(AppHandler.class);

    /* The singleton applet object */
    private static AppHandler singleton;

    /* The Applet or Application Main window who is referencing to */
    private MainWindow _mw = null;

    // This object interacts with the signature thread and wraps all the multisignature complexity
    public SignatureHandler sigh = null;

    // JavaScript Functions
    private String jsSignOk = "onSignOk";
    private String jsSignError = "onSignError";
    private String jsSignCancel = "onSignCancel";
    private String jsWindowShow = "onWindowShow";

    // Signature output format
    private SupportedSignatureFormat signatureFormat = SupportedSignatureFormat.CMS;

    // Input data encoding format
    private SupportedDataEncoding inputDataEncoding = SupportedDataEncoding.PLAIN;
    private SupportedDataEncoding outputDataEncoding = SupportedDataEncoding.PLAIN;

    // Host navigator
    private SupportedBrowser navigator = SupportedBrowser.MOZILLA;

    // Input/Output Data handling
    private InputParams input;
    private OutputParams output;

    // XAdES signer role customization
    private String[] signerRole;
    private String xadesFilename;
    private String xadesFileMimeType;
    private String[] xadesBaseRef;

    private boolean isBigFile = false;

    private SSLSocketFactory defaultSocketFactory;
    private String downloadURL;

    // PDF options

    private Map<String, String[]> bindValues;
    private String[] reason;
    private String[] location;
    private String[] contact;
    private String[] timestamping;
    private String[] tsaURL;
    private String[] visibleSignature;
    private String[] visibleSignatureType;
    private String[] visibleAreaX;
    private String[] visibleAreaY;
    private String[] visibleAreaX2;
    private String[] visibleAreaY2;
    private String[] visibleAreaPage;
    private String[] visibleAreaTextSize;
    private String[] visibleAreaImgFile;
    private String[] visibleAreaRepeatAxis;
    private String[] visibleAreaTextPattern;

    private boolean cosign;
    private boolean enveloped;
    private boolean detached;

    private String dniToCheckAgainsCertificate;

    private String[] documentReference;
    private String[] documentReferenceVerificationUrl;

    public AppHandler() throws SignatureAppletException
    {
        this(null);

        this.cosign = false;
        this.enveloped = true;

        log.debug("Running in desktop application mode");
    }

    /**
     * Base constructor, instantiates an AppHandler object, setting up the target navigator and
     * creating an available keystore mapping.
     * <p/>
     * That class should be used as a Sigleton so you must use getInstance in order to get this
     * class object.
     */

    public AppHandler(String downloadURL) throws SignatureAppletException
    {
        this.bindValues = new HashMap<String, String[]>();
        this.downloadURL = downloadURL;

        try
        {
            log.debug("Get JavaScript member: navigator");
            JSObject document = (JSObject) JSCommands.getWindow().getMember("navigator");

            log.debug("Get JavaScript member: userAgent");
            String userAgent = (String) document.getMember("userAgent");

            if (userAgent != null)
            {
                userAgent = userAgent.toLowerCase();

                log.debug("Detected user agent " + userAgent);
                log.debug("Is IE? " + SupportedBrowser.isIE(userAgent));
                log.debug("Is Win? " + OS.isWindowsUpperEqualToNT());
                log.debug("Is Chrome? " + SupportedBrowser.isChrome(userAgent));
                log.debug("Is Mozilla? " + SupportedBrowser.isMozilla(userAgent));

                if (SupportedBrowser.isIE(userAgent) || SupportedBrowser.isChromeWindows(userAgent))
                {
                    this.navigator = SupportedBrowser.IEXPLORER;

                    try
                    {
                        this.install();
                    }
                    catch (Throwable e)
                    {
                        log.error("Error installing or loading the DLL file", e);
                    }
                }
                else if (SupportedBrowser.isMozilla(userAgent))
                {
                    this.navigator = SupportedBrowser.MOZILLA;
                }
            }
        }
        catch (Exception exc)
        {
            log.error("Error accesing web browser window", exc);
        }

        log.debug("Navigator variable set to " + this.navigator);

        // Keep a copy to restore its value
        defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
    }

    /**
     * That method instantiates this Singleton class or returns the Object.
     */
    public static AppHandler getInstance(String downloadURL) throws SignatureAppletException
    {
        if (singleton == null)
        {
            singleton = new AppHandler(downloadURL);
        }

        return singleton;
    }

    /**
     * That method returns the appHandler object, the object must be previously instantiated.
     *
     * @return AppHandler The application handler object.
     */
    public static AppHandler getInstance() throws SignatureAppletException
    {
        if (singleton == null)
        {
            singleton = new AppHandler();
        }

        return singleton;
    }

    /**
     * Returns the Application invoker's main window for deal with him.
     *
     * @return MainWindow The MainWindow application object
     */
    public MainWindow getMainWindow()
    {
        return _mw;
    }

    /**
     * A method to obtain the selected inputParams depending on the input way (JS exported method)
     *
     * @return InputParams The inputParam class representing the input method.
     */
    public InputParams getInputParams()
    {
        return input;
    }

    /**
     * A method to obtain the selected outputParams depending on the output way (JS exported method)
     *
     * @return OutputParams The outputparam class representing the input method.
     */
    public OutputParams getOutputParams()
    {
        return output;
    }

    /**
     * A method for getting the selected signer role from setSignerRole JS function.
     *
     * @return signerRole The selected signerrole for XAdES output format
     */
    public String[] getSignerRole()
    {
        return signerRole;
    }

    /**
     * A method for getting the selected file name from setXadesFileName JS function.
     *
     * @return xadesFileName The selected file name for XAdES output format
     */
    public String getXadesFileName()
    {
        return this.xadesFilename;
    }

    /**
     * A method for getting the selected file Mime Type from setXadesFileName JS function.
     *
     * @return xadesFileName The selected file Mime Type for XAdES output format
     */
    public String getXadesFileMimeType()
    {
        return this.xadesFileMimeType;
    }

    /**
     * Returns a string representing the host browser over the applet is running
     *
     * @return string representing the browser
     */
    public SupportedBrowser getNavigator()
    {
        return this.navigator;
    }

    /**
     * A method for setting the signer role, that method is called from setSignerRole JS function.
     *
     * @param signerrole The signer role to be set for XAdES output format
     */
    public void setSignerRole(String[] signerrole)
    {
        this.signerRole = signerrole;
    }

    /**
     * A method for setting the filename, that method is called from setXadesFileName JS function.
     *
     * @param filename The file name to be set for XAdES output format
     */
    public void setXadesFileName(String filename)
    {
        this.xadesFilename = filename;
    }

    /**
     * A method for setting the selected file Mime Type from setXadesFileName JS function.
     */
    public void setXadesFileMimeType(String xadesFileMimeType)
    {
        this.xadesFileMimeType = xadesFileMimeType;
    }

    /**
     * This method sets a reference to the MainWindow's object.
     *
     * @param mw MainWindow application object
     */
    public void setMainWindow(MainWindow mw)
    {
        _mw = mw;
    }

    /**
     * Help method for install(), it downloads the dll and writes it down to the filesystem
     *
     * @param input  URL where get the data from.
     * @param output Destination path of the dll.
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
     * @throws SignatureAppletException with the message
     * @throws
     */
    public void installDLL(String dllDownloadUrl, String completeDllPath)
            throws SignatureAppletException
    {
        try
        {
            log.debug("Downloading " + dllDownloadUrl + ". Complete DLL path is " + completeDllPath);
            dumpFile(dllDownloadUrl, completeDllPath);
        }
        catch (Throwable e)
        {
            log.error(LabelManager.get("ERROR_CAPI_DLL_INSTALL"), e);
            throw new SignatureAppletException(LabelManager.get("ERROR_CAPI_DLL_INSTALL"));
        }
    }

    /**
     * Installs the applet on the client, basically downloads and loads MicrosoftCryptoApi dll
     *
     * @throws SignatureAppletException with the message
     * @throws
     */
    public void install() throws SignatureAppletException
    {
        String destAbsolutePath = System.getenv("TEMP");

        String microsoftCryptoApiDllName;
        byte[] originalDLLHash;
        if (OS.is64BitJava()) {
            microsoftCryptoApiDllName = "MicrosoftCryptoApi_x64_0_5.dll";
            originalDLLHash = new byte[]{(byte) 0xb5, 0x16, (byte) 0xde, (byte) 0xaf, (byte) 0xfa, (byte) 0xc4,
                    (byte) 0x2f, 0x0e, (byte) 0x01, 0x3f, (byte) 0x76, (byte) 0x35, (byte) 0x84, (byte) 0xdd, (byte) 0xdb,
                    (byte) 0xdd, (byte) 0x34, (byte) 0x35, (byte) 0xb1, (byte) 0x3b};
        } else {
            microsoftCryptoApiDllName = "MicrosoftCryptoApi_0_5.dll";
            originalDLLHash = new byte[]{(byte) 0xc5, 0x62, (byte) 0x98, (byte) 0xc8, (byte) 0x80, (byte) 0xeb,
                    (byte) 0x66, 0x02, (byte) 0xb9, 0x54, (byte) 0xeb, (byte) 0xae, (byte) 0xcb, (byte) 0xc2, (byte) 0xbf,
                    (byte) 0x52, (byte) 0x90, (byte) 0xed, (byte) 0x0b, (byte) 0xd7};
        }
        String completeDLLPath = destAbsolutePath + File.separator + microsoftCryptoApiDllName;
        File dllFile = new File(completeDLLPath);
        String dllDownloadUrl = this.downloadURL + microsoftCryptoApiDllName;
        if (!dllFile.exists())
        {

            log.info(microsoftCryptoApiDllName + " not found. Downloading DLL file");
            // FIXME hash is not being verified if the file doesn't exist already, this code is downloading and trusting immediately
            installDLL(dllDownloadUrl, completeDLLPath);
        }
        else
        {
            log.info( microsoftCryptoApiDllName + " already exists. Verifying existing DLL file");

            try
            {
                FileInputStream dllFileStream = new FileInputStream(dllFile);

                MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
                byte[] readed = new byte[dllFileStream.available()];

                dllFileStream.read(readed);
                messageDigest.update(readed);

                byte[] currentDLLHash = messageDigest.digest();

                log.debug("Original DLL digest: " + HexDump.xdump(originalDLLHash));
                log.debug("Current DLL digest: " + HexDump.xdump(currentDLLHash));

                // Compare original and current hash

                for (int i = 0; i < currentDLLHash.length; i++)
                {
                    if (currentDLLHash[i] != originalDLLHash[i])
                    {
                        log.info("DLL not valid. Downloading orginal DLL file");

                        installDLL(dllDownloadUrl, completeDLLPath);
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
            log.debug("Loading DLL with System.load " + completeDLLPath);

            System.load(completeDLLPath);
        }
        catch (Throwable e)
        {
            log.error("Error loading " + completeDLLPath, e);
        }
    }

    /**
     * Calls the javascript function indicated as func with params arguments
     *
     * @param func   The function that must be invoked
     * @param params The parameters that must be passed to that function
     */
    public void callJavaScriptCallbackFunction(String func, String[] params)
    {
        log.debug("Call JavaScript method: " + func);
        JSCommands.getWindow().call(func, params);
    }

    /**
     * Select the functions that must be called on signature ok, error and cancel
     *
     * @param onSignOk     The name of the function to be called on signature ok
     * @param onSignCancel The name of the function to be called on signature cancel
     * @param onSignError  The name of the function to be called on signature Error
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
     * @param jsSignCancel the name of the function to be called on cancel at DOM
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
     * @param jsSignError The name of the error function
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
     * @param jsSignOk The name of the function
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
     * It returns the selected output data encoding
     *
     * @return outputDataEncoding the selected input data encoding
     */
    public SupportedDataEncoding getOutputDataEncoding()
    {
        return this.outputDataEncoding;
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
     * A method for get the isBigFile attribute.
     *
     * @return boolean indicating if it is bigFile or not.
     */
    public boolean getIsBigFile()
    {
        return this.isBigFile;
    }

    /**
     * A method for setting the encoding type of the input data
     *
     * @param inputDataEncoding the encoding name
     */
    public void setInputDataEncoding(SupportedDataEncoding inputDataEncoding)
    {
        this.inputDataEncoding = inputDataEncoding;

        log.debug("Setting inputDataEncoding to " + inputDataEncoding);
    }

    /**
     * A method for setting the encoding type for the output data
     *
     * @param outputDataEncoding the encoding name
     */
    public void setOutputDataEncoding(SupportedDataEncoding outputDataEncoding)
    {
        this.outputDataEncoding = outputDataEncoding;

        log.debug("Setting inputDataEncoding to " + outputDataEncoding);
    }

    /**
     * Sets the InputParams for this signature
     *
     * @param input the InputParams implementation class
     */
    public void setInput(InputParams input)
    {
        this.input = input;
    }

    /**
     * Sets the OutputParams for this signature
     *
     * @param output the OutputParams implementation class
     */
    public void setOutput(OutputParams output)
    {
        this.output = output;
    }

    /**
     * This method computes the signature, that should be done by a thread
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

    /**
     * This method allow the user to disable the SSL server certificate validation when connecting
     * throughout an https connection
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
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager()
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
            }};

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

    public void setIsBigFile(boolean isBigFile)
    {
        System.out.println("SET ISBIGFILE to: " + isBigFile);
        this.isBigFile = isBigFile;
    }

    public void setXAdESBaseRef(String[] baseReference)
    {
        this.xadesBaseRef = baseReference;

    }

    public String[] getXAdESBaseRef()
    {
        return this.xadesBaseRef;
    }

    public static void initConfig(String downloadURL)
    {
        log.debug("Trying to retrieve ujiCrypto.conf from server ...");

        try
        {
            // Retrieve ujiCrypto.conf file
            URL url = new URL(downloadURL + "ujiCrypto.conf");
            URLConnection uc = url.openConnection();
            uc.connect();

            Properties properties = new Properties();
            properties.load(uc.getInputStream());

            // Load remote properties
            ConfigManager.getInstance(properties);

            log.debug("Remote ujiCrypto.conf loaded successfully!!");
        }
        catch (Exception e)
        {
            log.error("Cann't load ujiCrypto.conf from server. WARNING: Bundled local file will be loaded.");
        }
    }

    public Map<String, String[]> getBindValues()
    {
        return bindValues;
    }

    public void setBindValues(Map<String, String[]> bindValues)
    {
        this.bindValues = bindValues;
    }

    public String[] getReason()
    {
        return reason;
    }

    public void setReason(String[] reason)
    {
        this.reason = reason;
    }

    public String[] getLocation()
    {
        return location;
    }

    public void setLocation(String[] location)
    {
        this.location = location;
    }

    public String[] getContact()
    {
        return contact;
    }

    public void setContact(String[] contact)
    {
        this.contact = contact;
    }

    public String[] getTimestamping()
    {
        return timestamping;
    }

    public void setTimestamping(String[] timestamping)
    {
        this.timestamping = timestamping;
    }

    public String[] getTsaURL()
    {
        return tsaURL;
    }

    public void setTsaURL(String[] tsaURL)
    {
        this.tsaURL = tsaURL;
    }

    public String[] getVisibleSignature()
    {
        return visibleSignature;
    }

    public void setVisibleSignature(String[] visibleSignature)
    {
        this.visibleSignature = visibleSignature;
    }

    public String[] getVisibleSignatureType()
    {
        return visibleSignatureType;
    }

    public void setVisibleSignatureType(String[] visibleSignatureType)
    {
        this.visibleSignatureType = visibleSignatureType;
    }

    public String[] getVisibleAreaX()
    {
        return visibleAreaX;
    }

    public void setVisibleAreaX(String[] visibleAreaX)
    {
        this.visibleAreaX = visibleAreaX;
    }

    public String[] getVisibleAreaY()
    {
        return visibleAreaY;
    }

    public void setVisibleAreaY(String[] visibleAreaY)
    {
        this.visibleAreaY = visibleAreaY;
    }

    public String[] getVisibleAreaX2()
    {
        return visibleAreaX2;
    }

    public void setVisibleAreaX2(String[] visibleAreaX2)
    {
        this.visibleAreaX2 = visibleAreaX2;
    }

    public String[] getVisibleAreaY2()
    {
        return visibleAreaY2;
    }

    public void setVisibleAreaY2(String[] visibleAreaY2)
    {
        this.visibleAreaY2 = visibleAreaY2;
    }

    public String[] getVisibleAreaPage()
    {
        return visibleAreaPage;
    }

    public void setVisibleAreaPage(String[] visibleAreaPage)
    {
        this.visibleAreaPage = visibleAreaPage;
    }

    public String[] getVisibleAreaTextSize()
    {
        return visibleAreaTextSize;
    }

    public void setVisibleAreaTextSize(String[] visibleAreaTextSize)
    {
        this.visibleAreaTextSize = visibleAreaTextSize;
    }

    public String[] getVisibleAreaImgFile()
    {
        return visibleAreaImgFile;
    }

    public void setVisibleAreaImgFile(String[] visibleAreaImgFile)
    {
        this.visibleAreaImgFile = visibleAreaImgFile;
    }

    public String[] getVisibleAreaRepeatAxis()
    {
        return visibleAreaRepeatAxis;
    }

    public void setVisibleAreaRepeatAxis(String[] visibleAreaRepeatAxis)
    {
        this.visibleAreaRepeatAxis = visibleAreaRepeatAxis;
    }

    public String[] getVisibleAreaTextPattern()
    {
        return visibleAreaTextPattern;
    }

    public void setVisibleAreaTextPattern(String[] visibleAreaTextPattern)
    {
        this.visibleAreaTextPattern = visibleAreaTextPattern;
    }

    public void setSignatureFormat(SupportedSignatureFormat signatureFormat)
    {
        this.signatureFormat = signatureFormat;
    }

    public boolean isCosign()
    {
        return cosign;
    }

    public void setCosign(boolean cosign)
    {
        this.cosign = cosign;
    }

    public boolean isEnveloped()
    {
        return enveloped;
    }

    public void setEnveloped(boolean enveloped)
    {
        this.enveloped = enveloped;
    }

    public void setDNIToCheckAgainsCertificate(String dni)
    {
        this.dniToCheckAgainsCertificate = dni;
    }

    public String getDniToCheckAgainsCertificate()
    {
        return this.dniToCheckAgainsCertificate;
    }

    public String[] getDocumentReference()
    {
        return documentReference;
    }

    public void setDocumentReference(String[] documentReference)
    {
        this.documentReference = documentReference;
    }

    public String[] getDocumentReferenceVerificationUrl()
    {
        return documentReferenceVerificationUrl;
    }

    public void setDocumentReferenceVerificationUrl(String[] documentReferenceVerificationUrl)
    {
        this.documentReferenceVerificationUrl = documentReferenceVerificationUrl;
    }

    public boolean isDetached()
    {
        return detached;
    }

    public void setDetached(boolean detached)
    {
        this.detached = detached;
    }
}

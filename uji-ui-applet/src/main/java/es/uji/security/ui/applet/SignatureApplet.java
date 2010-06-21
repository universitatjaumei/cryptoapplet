package es.uji.security.ui.applet;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;

import javax.swing.JApplet;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import netscape.javascript.JSException;

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import es.uji.security.crypto.SupportedBrowser;
import es.uji.security.crypto.SupportedDataEncoding;
import es.uji.security.crypto.SupportedSignatureFormat;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.Device;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.openxades.OpenXAdESSignatureVerifier;
import es.uji.security.keystore.DeviceInitializationException;
import es.uji.security.keystore.KeyStoreManager;
import es.uji.security.ui.applet.io.ConsoleOutputParams;
import es.uji.security.ui.applet.io.FileInputParams;
import es.uji.security.ui.applet.io.FuncOutputParams;
import es.uji.security.ui.applet.io.ParamInputData;
import es.uji.security.ui.applet.io.URLInputParams;
import es.uji.security.ui.applet.io.URLOutputParams;
import es.uji.security.util.i18n.LabelManager;

/**
 * This is the main applet class, it handles the web-to-java interaction by exporting some method to
 * JavaScript for being invoked within a web page.
 * 
 * The instantiation inside a web page must be in this way:
 * 
 * <applet id="CryptoApplet" name="CryptoApplet" code="es.uji.dsign.applet.SignatureApplet"
 * width="0" height="0" codebase="path" archive="archive and deps mayscript> </applet>
 * 
 * Each method below related to setup or signature forgery can be invoked from JavaScript
 */

@SuppressWarnings("serial")
public class SignatureApplet extends JApplet
{
    private Logger log = Logger.getLogger(SignatureApplet.class);

    private AppHandler apph;
    private MainWindow window;
    private String _separator = "\\|";
    private String appletTag;
    private String appletInput;
    private String appletOutput;

    private KeyStoreManager keyStoreManager;

    /**
     * Init method. Installs the applet on client side. Downloads MicrosoftCryptoApi dll and loads
     * it in case of Internet Explorer
     */

    static
    {
        // Para evitar que pida cosas del log4j
        System.setProperty("log4j.defaultInitOverride", "true");

        BasicConfigurator.resetConfiguration();

        Layout layout = new PatternLayout("%p %t %c [%d{HH:mm:ss,SSS}] - %m%n");
        Appender appender = new ConsoleAppender(layout);
        BasicConfigurator.configure(appender);

        Logger.getRootLogger().setLevel(Level.DEBUG);

        // Para evitar que pida .class varios
        System.setProperty("javax.xml.parsers.SAXParserFactory",
                "com.sun.org.apache.xerces.internal.jaxp.SAXParserFactoryImpl");
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
        System.setProperty("javax.xml.transform.TransformerFactory",
                "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
        System.setProperty("org.apache.xml.dtm.DTMManager",
                "org.apache.xml.dtm.ref.DTMManagerDefault");
    }

    public void init()
    {
        // Init JavaScript interface

        try
        {
            JSCommands.clearInstance();
            JSCommands.getInstance(this);
        }
        catch (Exception e)
        {
            log.error("Error with JSCommands init", e);
        }

        // Init Nimbus Look&Feel if available (JDK1.6u10 or higher)

        try
        {
            log.debug("Looking for suitable Look&Feels");

            for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels())
            {
                if ("Nimbus".equals(info.getName()))
                {
                    UIManager.setLookAndFeel(info.getClassName());
                    log.debug("Nimbus Look&Feel loaded");

                    break;
                }
            }
        }
        catch (Exception e)
        {
            log.error("Nimbus Look&Feel is not present. Using default Look&Feel");
        }

        try
        {
            String downloadURL = "";

            if (this.getParameter("downloadUrl") != null)
            {
                downloadURL = this.getParameter("downloadUrl");
            }
            else
            {
                downloadURL = this.getCodeBase().toString();
            }

            this.apph = AppHandler.getInstance(downloadURL);
            this.keyStoreManager = new KeyStoreManager();

            // Init config (try to load ujiCrypto.conf from server)

            AppHandler.initConfig(downloadURL);

            // Init keystores

            this.initKeystores(this.apph.getNavigator());

            // Call onInitOk

            log.debug("Call JavaScript method: onInitOk");
            JSCommands.getWindow().call("onInitOk", new String[] {});
        }
        catch (Exception e)
        {
            log.error(e);
            JOptionPane.showMessageDialog(null, e.getMessage(), "", JOptionPane.ERROR_MESSAGE);

            log.debug("Call JavaScript method: onSignError");
            JSCommands.getWindow().call("onSignError", new String[] {});
        }
    }

    /**
     * Try to load storege devices: Navigator store, Clauer UJI store and PKCS11 configured stores
     * 
     * @param supportedBrowser
     */

    private void initKeystores(SupportedBrowser supportedBrowser)
    {
        this.keyStoreManager.flushKeyStoresTable();
        this.keyStoreManager.initBrowserStores(apph.getNavigator());

        if (!supportedBrowser.equals(SupportedBrowser.IEXPLORER))
        {
            this.keyStoreManager.initClauer();

            ConfigManager conf = ConfigManager.getInstance();

            for (Device device : conf.getDeviceConfig())
            {
                try
                {
                    keyStoreManager.initPKCS11Device(device, null);
                }
                catch (DeviceInitializationException die)
                {
                    for (int i = 0; i < 3; i++)
                    {
                        PasswordPrompt passwordPrompt = new PasswordPrompt(null, device.getName(),
                                "Pin:");

                        try
                        {
                            this.keyStoreManager.initPKCS11Device(device, passwordPrompt
                                    .getPassword());
                            break;
                        }
                        catch (Exception e)
                        {
                            JOptionPane
                                    .showMessageDialog(null, LabelManager
                                            .get("ERROR_INCORRECT_DNIE_PWD"), "",
                                            JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
        }
    }

    public KeyStoreManager getKeyStoreManager()
    {
        return this.keyStoreManager;
    }

    private void initializeWindow()
    {
        log.debug("Init window");

        try
        {
            if (window == null)
            {
                window = new MainWindow(this.keyStoreManager, this.apph);
            }
            else
            {
                window.getPasswordTextField().setText("");
                window.getGlobalProgressBar().setValue(0);
                window.getInformationLabelField().setText(LabelManager.get("SELECT_A_CERTIFICATE"));

                this.initKeystores(this.apph.getNavigator());

                window.reloadCertificateJTree();
                window.getMainFrame().setVisible(true);
                window.getShowSignatureCheckBox().setVisible(true);
            }
        }
        catch (Exception ex)
        {
            log.error(ex);
            JOptionPane.showMessageDialog(null, ex.getMessage(), "", JOptionPane.ERROR_MESSAGE);

            try
            {
                log.debug("Call JavaScript method: " + apph.getJsSignError());
                JSCommands.getWindow().call(apph.getJsSignError(), new String[] { "" });
            }
            catch (JSException e)
            {
                log.error("Error calling " + apph.getJsSignError(), e);
            }
        }

        try
        {
            log.debug("Call JavaScript method: " + apph.getJsWindowShow());
            JSCommands.getWindow().call(apph.getJsWindowShow(), new String[] { "" });
        }
        catch (JSException e)
        {
            log.error("Error calling " + apph.getJsWindowShow(), e);
        }
    }

    /**
     * This method sets up the applet language, possible values are: ES_es for spanish CA_ca for
     * EN_en
     * 
     * @param lang
     *            true means ask for it, false means keep the last correct config.
     */

    public void setLanguage(final String lang)
    {
        // We grant to JavaScript the same privileges as the core applet

        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                LabelManager.setLang(lang);
                return null;
            }
        });
    }

    /**
     * Allow override the default three JavaScript functions OnSignOk, OnSignCancel and OnSignError
     * those functions are called when the process was success, user cancelled or an error happened
     * respectively
     * 
     * @param ok
     *            The name of the JavaSript function will be called on success
     * @param cancel
     *            The name of the JavaSript function will be called on user cancel
     * @param error
     *            The name of the JavaSript function will be called on error
     */
    public void setJavaScriptCallbackFunctions(final String ok, final String error,
            final String cancel, final String windowShow)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setJavaScriptCallbackFunctions(ok, error, cancel, windowShow);
                return null;
            }
        });
    }

    /**
     * The invocation of this function is mandatory, the client must set up with this function the
     * type of signature format he want
     * 
     * @param format
     *            Possible values are the Strings: RAW, CMS, XADES or PDF
     */

    public void setSignatureOutputFormat(final String format)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setSignatureOutputFormat(SupportedSignatureFormat
                        .valueOf(format.toUpperCase()));
                return null;
            }
        });
    }

    /**
     * Sets the input encoding, if the input is different that plain, the applet will decodify the
     * input before computing the signature
     * 
     * @param encoding
     *            Possible values PLAIN, HEX, BASE64
     */

    public void setInputDataEncoding(final String encoding)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setInputDataEncoding(SupportedDataEncoding.valueOf(encoding));
                return null;
            }
        });
    }

    /**
     * Sets the output encoding, if the input is different that plain, the applet will codify the
     * output after computing the signature
     * 
     * @param encoding
     *            Possible values PLAIN, HEX, BASE64
     */

    public void setOutputDataEncoding(final String encoding)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setOutputDataEncoding(SupportedDataEncoding.valueOf(encoding.toUpperCase()));
                return null;
            }
        });
    }

    /**
     * Sets the input encoding, if the input is different that plain, the applet will decodify the
     * input before computing the signature
     * 
     * @param encoding
     *            Possible values PLAIN, HEX, BASE64
     */

    public void setSSLServerCertificateVerification(final String value)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setSSLCertificateVerfication(!(value.trim().equals("false")));
                return null;
            }
        });
    }

    /**
     * JS interface to setting the XAdES signer role from Navigator's javascript
     * 
     * @param signerrole
     */
    public void setXadesSignerRole(final String signerrole)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {

                String[] sr_arr = signerrole.split(_separator);

                apph.setSignerRole(sr_arr);
                return null;
            }
        });
    }

    /**
     * JS interface to setting the XAdES main reference id from Navigator's javascript
     * 
     * @param id
     */
    public void setXadesBaseReference(final String baseReference)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] refs = baseReference.split(_separator);
                apph.setXAdESBaseRef(refs);
                return null;
            }
        });
    }

    /**
     * JS interface to setting the XAdES file name from Navigator's javascript
     * 
     * @param filename
     */
    public void setXadesFileName(final String filename)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setXadesFileName(filename);
                return null;
            }
        });
    }

    /**
     * JS interface to setting the XAdES file Mime type from Navigator's javascript
     * 
     * @param filename
     */
    public void setXadesFileMimeType(final String mimetype)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setXadesFileMimeType(mimetype);
                return null;
            }
        });
    }

    /**
     * JS interface to setting the bigFile support. It must be set if the file can overflow the
     * memory because of its size.
     * 
     * @param String
     *            "true" or "false"
     */
    public void setIsBigFile(final String bigfile)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setIsBigFile(bigfile.equals("true"));
                return null;
            }
        });
    }

    /* SIGNATURE COMPUTATION FUNCTIONS */

    /**
     * Computes the signature with the given toSign input data, if everything is correct, the applet
     * invokes funcOut with the resulting signature object as the function parameter.
     * 
     * @param toSign
     *            the data to be signed
     * @param funcOut
     *            the JavaScript function that must be called on success with the signature object
     *            as a result.
     */

    public void signDataParamToFunc(final String toSign, final String funcOut)
    {
        final SignatureApplet sa = this;
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                /*
                 * We construct the hash table in order to pass it to the applet handler for
                 * signature porpouses
                 */

                String[] arr = new String[] { toSign };

                ParamInputData input = new ParamInputData(arr);
                FuncOutputParams output = new FuncOutputParams(sa, funcOut);

                apph.setInput(input);
                apph.setOutput(output);

                initializeWindow();

                return null;
            }
        });
    }

    /**
     * Computes the signature with the given toSign input data, if everything is correct, the applet
     * invoke s funcOut with the resulting signature object as the function parameter.
     * 
     * @param toSign
     *            the data to be signed
     * @param funcOut
     *            the JavaScript function that must be called on success with the signature object
     *            as a result.
     * @param separator
     *            The characters that must be matched in order to break the string.
     */

    public void signDataParamToFunc(final String toSign, final String funcOut,
            final String separator)
    {
        final SignatureApplet sa = this;
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {

                String[] arr = toSign.split(separator);

                ParamInputData input = new ParamInputData(toSign.split(separator));
                FuncOutputParams output = new FuncOutputParams(sa, funcOut);
                output.setCount(arr.length);

                apph.setInput(input);
                apph.setOutput(output);

                initializeWindow();

                return null;
            }
        });
    }

    /**
     * Computes the signature with the given toSign input data, if everything is correct, the applet
     * make a POST to the outputURL with the resulting signature object in the "content" variable,
     * it also send to that URL the cookies for the current website.
     * 
     * @param toSign
     *            the data to be signed
     * @param outputURL
     *            the URL where the data must be POSTed
     */

    public void signDataParamToURL(final String toSign, final String outputURL)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {

                ParamInputData input = new ParamInputData(new String[] { toSign });
                URLOutputParams output = new URLOutputParams(new String[] { outputURL });
                apph.setInput(input);
                apph.setOutput(output);
                initializeWindow();

                return null;
            }
        });
    }

    /**
     * Computes the signature with the given toSign input data, if everything is correct, the applet
     * make a POST to the outputURL with the resulting signature object in the postVariableName, it
     * also send to that URL the cookies for the current website.
     * 
     * @param toSign
     *            the data to be signed
     * @param outputURL
     *            the URL where the data must be POSTed
     * @param postVariableName
     *            the name of the post variable to use, content by default.
     */

    public void signDataParamToURL(final String toSign, final String outputURL,
            final String postVariableName)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] arr = new String[] { toSign };

                ParamInputData input = new ParamInputData(arr);
                URLOutputParams output = new URLOutputParams(new String[] { outputURL },
                        postVariableName);

                apph.setInput(input);
                apph.setOutput(output);

                initializeWindow();

                return null;
            }
        });
    }

    /**
     * Computes the signature getting the data from the given inputURL, and it does a POST to the
     * outputURL with the signature object in the "content" variable. An item variable is passed by
     * the post method if inputURLs was a comma separated list of URL sources. That item variable is
     * incremented from 1 to n so the first one is item=1 the second item=2 and so on.
     * 
     * @param inputURL
     *            the URL where the data must be retrieved.
     * @param outputURL
     *            the URL where the data must be POSTed
     */

    public void signDataUrlToUrl(final String inputURLs, final String outputURLs)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] in = inputURLs.split(_separator);
                String[] out = outputURLs.split(_separator);

                URLInputParams input = new URLInputParams(in);
                URLOutputParams output = new URLOutputParams(out);

                output.setOutputCount(in.length);

                apph.setInput(input);
                apph.setOutput(output);
                System.out.println("Initializing Window ... ");
                initializeWindow();
                System.out.println("Window  initialized");

                return null;
            }
        });
    }

    /**
     * Computes the signature getting the data from the given inputURL, and it does a POST to the
     * outputURL with the signature object in the postVariableName variable. An item variable is
     * passed by the post method if inputURLs was a comma separated list of URL sources. That item
     * variable is incremented from 0 to n.
     * 
     * @param inputURL
     *            the URL where the data must be retrieved.
     * @param outputURL
     *            the URL where the data must be POSTed
     * @param postVariable
     *            the name of the post variable to use, content by default.
     */

    public void signDataUrlToUrl(final String inputURLs, final String outputURLs,
            final String postVariableName)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] in = inputURLs.split(_separator);
                String[] out = outputURLs.split(_separator);

                URLInputParams input = new URLInputParams(in);
                URLOutputParams output = new URLOutputParams(out, postVariableName);

                output.setOutputCount(in.length);

                apph.setInput(input);
                apph.setOutput(output);

                initializeWindow();
                return null;
            }
        });
    }

    /**
     * Computes the signature getting the data from the given inputURL, and it invokes JavaScript
     * funcOut with the signature object as a parameter.
     * 
     * @param inputURL
     *            the URL where the data must be retrieved.
     * @param funcOut
     *            the output JavaScript function name.
     */

    public void signDataUrlToFunc(final String inputURLs, final String funcOut)
    {
        final SignatureApplet sa = this;
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] in = inputURLs.split(_separator);

                URLInputParams input = new URLInputParams(in);
                FuncOutputParams output = new FuncOutputParams(sa, funcOut);

                apph.setInput(input);
                apph.setOutput(output);

                initializeWindow();
                return null;
            }
        });
    }

    /**
     * Computes the signature getting the hash of the data as a parameter, and giving the result as
     * a parameter for funcOut JavaScript function. The hash must be encoded as an hex string or as
     * 
     * This method only works with CMS output format signature.
     * 
     * @param toSign
     *            the hash to be signed.
     * @param funcOut
     *            the output JavaScript function name.
     * 
     */

    public void signHashParamToFunc(String toSign, String funcOut)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                // TODO: CALL FUNC
                return null;
            }
        });
    }

    /**
     * Computes the signature getting the hash of the data as a parameter, and giving the result as
     * a POST to the "outputURL" URL with the content in the variable named "content". The hash must
     * be encoded as an hex string or as
     * 
     * This method only works with CMS output format signature.
     * 
     * @param toSign
     *            the hash to be signed.
     * @param outputURL
     *            the output JavaScript function name.
     */

    public void signHashParamlToUrl(String toSign, String outputURL)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                // TODO: CALL FUNC
                return null;
            }
        });
    }

    /**
     * Computes the signature getting the hash of the data as a parameter, and giving the result as
     * a POST to the "outputURL" URL with the content in the variable postVariableName (content by
     * default). The hash must be encoded as an hex string or as
     * 
     * This method only works with CMS output format signature.
     * 
     * @param toSign
     *            the hash to be signed.
     * @param outputURL
     *            the output JavaScript function name.
     * @param postVariableName
     *            the variable name for the post.
     */

    public void signHashParamlToUrl(String toSign, String outputURL, String[] postVariableName)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                // TODO: CALL FUNC
                return null;
            }
        });
    }

    /**
     * 
     * This function allow to set which certificate is allowed to sign.
     * 
     * @param Issuer
     *            In a ... format
     * @param SerialNo
     *            In a ... format
     */

    public void setAllowedCertificate(final String Issuer, final String SerialNo)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                // apph.setSignatureOutputFormat(format);
                return null;
            }
        });
    }

    /* VERIFICATION FUNCTIONS */

    /**
     * Allow signature verification for Xades types
     * 
     * @param input
     *            The URL string where de data must be got.
     * 
     * @return res an String[] vector indicating the causes of the signature, null return shows
     *         correct signature
     */
    public String[] verifyXAdESDataUrl(final String input)
    {
        String[] res = AccessController.doPrivileged(new PrivilegedAction<String[]>()
        {
            public String[] run()
            {

                OpenXAdESSignatureVerifier sv = new OpenXAdESSignatureVerifier();

                try
                {
                    URL url = new URL(input);

                    URLConnection uc = url.openConnection();
                    uc.connect();
                    InputStream in = uc.getInputStream();

                    byte[] data = OS.inputStreamToByteArray(in);

                    VerificationResult verificationDetails = sv.verify(data);
                    return verificationDetails.getErrorsAsStringArray();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    return new String[] { e.getMessage() };
                }
            }
        });
        return (String[]) res;
    }

    public void setBindValue(final String key, final String value)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = value.split(_separator);
                apph.getBindValues().put(key, values);
                
                return null;
            }
        });
    }

    public void setReason(final String reason)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = reason.split(_separator);
                apph.setReason(values);
                
                return null;
            }
        });
    }

    public void setLocation(final String location)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = location.split(_separator);
                apph.setLocation(values);
                
                return null;
            }
        });
    }

    public void setContact(final String contact)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = contact.split(_separator);
                apph.setContact(values);
                
                return null;
            }
        });
    }

    public void setTimestamping(final String timestamping)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = timestamping.split(_separator);
                apph.setTimestamping(values);
                
                return null;
            }
        });
    }

    public void setTsaURL(final String tsaURL)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = tsaURL.split(_separator);
                apph.setTsaURL(values);
                
                return null;
            }
        });
    }

    public void setVisibleSignature(final String visibleSignature)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleSignature.split(_separator);
                apph.setVisibleSignature(values);
                
                return null;
            }
        });
    }

    public void setVisibleSignatureType(final String visibleSignatureType)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleSignatureType.split(_separator);
                apph.setVisibleSignatureType(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaX(final String visibleAreaX)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaX.split(_separator);
                apph.setVisibleAreaX(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaY(final String visibleAreaY)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaY.split(_separator);
                apph.setVisibleAreaY(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaX2(final String visibleAreaX2)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaX2.split(_separator);
                apph.setVisibleAreaX2(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaY2(final String visibleAreaY2)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaY2.split(_separator);
                apph.setVisibleAreaY2(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaPage(final String visibleAreaPage)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaPage.split(_separator);
                apph.setVisibleAreaPage(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaTextSize(final String visibleAreaTextSize)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaTextSize.split(_separator);
                apph.setVisibleAreaTextSize(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaImgFile(final String visibleAreaImgFile)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaImgFile.split(_separator);
                apph.setVisibleAreaImgFile(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaRepeatAxis(final String visibleAreaRepeatAxis)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaRepeatAxis.split(_separator);                
                apph.setVisibleAreaRepeatAxis(values);
                
                return null;
            }
        });
    }

    public void setVisibleAreaTextPattern(final String visibleAreaTextPattern)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                String[] values = visibleAreaTextPattern.split(_separator);
                apph.setVisibleAreaTextPattern(values);
                
                return null;
            }
        });
    }

    public void setSignatureFormat(final SupportedSignatureFormat signatureFormat)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                apph.setSignatureFormat(signatureFormat);
                
                return null;
            }
        });
    }

    /**
     * Test the execution environment, is everything ok to do the signature.
     * 
     */
    public void doTest()
    {
        final SignatureApplet signatureApplet = this;

        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                AppEnvironmentTester aen = new AppEnvironmentTester(signatureApplet);
                aen.setAppletHandler(apph);
                aen.setup(appletTag, appletInput, appletOutput);
                aen.start();
                return null;
            }
        });
    }

    public void testSetup(String appletTag, String input, String output)
    {
        this.appletTag = appletTag;
        this.appletInput = input;
        this.appletOutput = output;
    }

    public void destroy()
    {
        super.destroy();
        Runtime.getRuntime().gc();

        log.debug("Applet destoy called. Executing garbage collection");
    }

    public String getAppletInfo()
    {
        return "Universitat Jaume I: CryptoApplet for multiformat digital signature generation";
    }

    public String getAppletVersion()
    {
        return "2.1.1";
    }

    public String getJavaVersion()
    {
        return System.getProperty("java.version");
    }

    public static void main(String args[])
    {
        try
        {
            SignatureApplet signatureApplet = new SignatureApplet();
            AppHandler apph = AppHandler.getInstance();

            apph.setInput(new FileInputParams());
            apph.setOutput(new ConsoleOutputParams());
            apph.setInputDataEncoding(SupportedDataEncoding.PLAIN);
            apph.setSignatureOutputFormat(SupportedSignatureFormat.XADES);

            signatureApplet.apph = apph;
            signatureApplet.keyStoreManager = new KeyStoreManager();

            signatureApplet.initKeystores(SupportedBrowser.MOZILLA);

            MainWindow window = new MainWindow(signatureApplet.keyStoreManager, apph);
            window.getMainFrame().setSize(590, 520);
            window.getMainFrame().setResizable(true);
            window.repaint();
        }
        catch (Exception ee)
        {
            ee.printStackTrace();
        }
    }
}

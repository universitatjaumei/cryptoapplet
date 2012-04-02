package es.uji.security.ui.applet;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JApplet;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import es.uji.security.crypto.DataEncoding;
import es.uji.security.crypto.SignatureFormat;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.keystore.KeyStoreManager;
import es.uji.security.ui.applet.io.URLInputParams;
import es.uji.security.ui.applet.io.URLOutputParams;
import es.uji.security.util.i18n.LabelManager;

@SuppressWarnings("serial")
public class SignatureApplet extends JApplet
{
    private Logger log = Logger.getLogger(SignatureApplet.class);

    private KeyStoreManager keyStoreManager;

    private JSCommands jsCommands;
    private SSLSocketFactory defaultSocketFactory;

    private SignatureFormat outputSignatureFormat;
    private DataEncoding outputDataEncoding;
    private DataEncoding inputDataEncoding;
    private boolean sslCertificateVerfication;
    private List<String> inputURLs;
    private List<String> outputURLs;
    private String dniToCheckCertificateAgainst;
    private Map<String, List<String>> signatureProperties;

    private MainWindow ui;

    static
    {
        initLog4jConfiguration();
        initSystemFactoryDefinitions();
    }

    private static void initSystemFactoryDefinitions()
    {
        System.setProperty("javax.xml.parsers.SAXParserFactory",
                "com.sun.org.apache.xerces.internal.jaxp.SAXParserFactoryImpl");
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
        System.setProperty("javax.xml.transform.TransformerFactory",
                "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");
        System.setProperty("org.apache.xml.dtm.DTMManager",
                "org.apache.xml.dtm.ref.DTMManagerDefault");
    }

    private static void initLog4jConfiguration()
    {
        System.setProperty("log4j.defaultInitOverride", "true");

        BasicConfigurator.resetConfiguration();

        Layout layout = new PatternLayout("%p %t %c [%d{HH:mm:ss,SSS}] - %m%n");
        Appender appender = new ConsoleAppender(layout);
        BasicConfigurator.configure(appender);

        Logger.getRootLogger().setLevel(Level.DEBUG);
    }

    public SignatureApplet()
    {
        this.signatureProperties = new HashMap<String, List<String>>();
    }

    public SignatureApplet(JSCommands jsCommands)
    {
        this.jsCommands = jsCommands;
    }

    public void init()
    {
        initLookAndFeel();
        initJavaScriptCommandExecution();
        loadRemotePropertiesConfigFile();

        try
        {
            keyStoreManager = new KeyStoreManager(jsCommands.getSupportedBrowser());
            keyStoreManager.initKeyStores();

            jsCommands.onInitOk();
        }
        catch (Exception e)
        {
            log.error(e);
            jsCommands.onSignError();
        }

        defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
    }

    private void initJavaScriptCommandExecution()
    {
        if (jsCommands == null)
        {
            jsCommands = JSCommands.getInstance(this);
        }
    }

    private void loadRemotePropertiesConfigFile()
    {
        try
        {
            String baseURL = ".";

            if (this.getCodeBase() != null)
            {
                baseURL = this.getCodeBase().toString();
            }

            ConfigManager.getInstance().loadRemotePropertiesFile(baseURL);
        }
        catch (Exception e)
        {
        }
    }

    private void initLookAndFeel()
    {
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
    }

    public void showUI()
    {
        try
        {
            ui = MainWindow.getInstance(keyStoreManager, jsCommands);
            ui.getPasswordTextField().setText("");
            ui.getGlobalProgressBar().setValue(0);
            ui.getInformationLabelField().setText(LabelManager.get("SELECT_A_CERTIFICATE"));
            ui.reloadCertificateJTree();
            ui.show();

            jsCommands.onWindowShow();
        }
        catch (Exception ex)
        {
            log.error(ex);
            jsCommands.onSignError();
        }
    }

    public void setLanguage(final String lang)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                LabelManager.setLang(lang);
                return null;
            }
        });
    }

    public void setOutputSignatureFormat(final String format)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                outputSignatureFormat = SignatureFormat.valueOf(format.toUpperCase());
                return null;
            }
        });
    }

    public void setOutputDataEncoding(final String encoding)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                outputDataEncoding = DataEncoding.valueOf(encoding.toUpperCase());
                return null;
            }
        });
    }

    public void setInputDataEncoding(final String encoding)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                inputDataEncoding = DataEncoding.valueOf(encoding);
                return null;
            }
        });
    }

    public void setSSLServerCertificateVerification(final String value)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                initSSLServerCertificateVerification(Boolean.parseBoolean(value));
                return null;
            }
        });
    }

    private void initSSLServerCertificateVerification(boolean validate)
    {
        if (validate)
        {
            HttpsURLConnection.setDefaultSSLSocketFactory(defaultSocketFactory);
        }
        else
        {
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

            try
            {
                SSLContext sc = SSLContext.getInstance("SSL");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            }
            catch (Exception e)
            {
                log.error(e);
            }
        }
    }

    public void addInputURL(final String inputURL)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                inputURLs.add(inputURL);
                return null;
            }
        });
    }

    public void addOutputURL(final String outputURL)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                outputURLs.add(outputURL);
                return null;
            }
        });
    }

    public void setDNIToCheckAgainsCertificate(final String dni)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                dniToCheckCertificateAgainst = dni;
                return null;
            }
        });
    }

    public void addProperty(final String propertyName, final String propertyValue)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                if (signatureProperties.containsKey(propertyName))
                {
                    signatureProperties.get(propertyName).add(propertyValue);
                }
                else
                {
                    signatureProperties.put(propertyName, Collections.singletonList(propertyValue));
                }

                return null;
            }
        });
    }

    public void sign()
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                URLInputParams input = new URLInputParams(inputURLs);
                URLOutputParams output = new URLOutputParams(outputURLs);

                showUI();

                return null;
            }
        });
    }

    public void destroy()
    {
        log.debug("Applet destroy called");
        super.destroy();
    }

    public String getAppletInfo()
    {
        return "Universitat Jaume I: CryptoApplet for multiformat digital signature generation";
    }

    public String getAppletVersion()
    {
        return "3.0.0";
    }

    public String getJavaVersion()
    {
        return System.getProperty("java.version");
    }

    public KeyStoreManager getKeyStoreManager()
    {
        return keyStoreManager;
    }

    public void setKeyStoreManager(KeyStoreManager keyStoreManager)
    {
        this.keyStoreManager = keyStoreManager;
    }
}
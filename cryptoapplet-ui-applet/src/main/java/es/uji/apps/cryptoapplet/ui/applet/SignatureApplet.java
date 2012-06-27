package es.uji.apps.cryptoapplet.ui.applet;

import java.security.AccessController;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.swing.JApplet;

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.i18n.LabelManager;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.raw.RawFormatter;
import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;

@SuppressWarnings("serial")
public class SignatureApplet extends JApplet
{
    private Logger log = Logger.getLogger(SignatureApplet.class);

    private KeyStoreManager keyStoreManager;
    private SignatureConfiguration signatureConfiguration;
    private HttpConnectionConfiguration connectionConfiguration;

    private ConfigManager configManager;
    private LabelManager labelManager;

    private Browser browser;

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

        Layout layout = new PatternLayout("%d %-5p %c:%L - %m%n");
        Appender appender = new ConsoleAppender(layout);
        BasicConfigurator.configure(appender);

        Logger.getRootLogger().setLevel(Level.DEBUG);
    }

    public SignatureApplet()
    {
        this.signatureConfiguration = new SignatureConfiguration();
        this.connectionConfiguration = new HttpConnectionConfiguration();
    }

    public void init()
    {
        loadConfiguration();

        browser = Browser.getInstance(this);

        try
        {
            labelManager = new LabelManager();

            keyStoreManager = new KeyStoreManager(browser.getDetectedBrowser());
            keyStoreManager.initKeyStores();

            browser.initOk();
        }
        catch (Exception e)
        {
            log.error("", e);
            browser.signError();
        }
    }

    private void loadConfiguration()
    {
        String baseURL = ".";

        if (this.getCodeBase() != null)
        {
            baseURL = this.getCodeBase().toString();
        }

        try
        {
            configManager = new ConfigManager(baseURL);
        }
        catch (ConfigurationLoadException e)
        {
            log.error("Problem loading configuration file", e);
            throw new RuntimeException(e);
        }
    }

    public void setLanguage(final String language)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    labelManager = new LabelManager(new Locale(language));
                }
                catch (Exception e)
                {
                    log.error(e);
                }

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
                signatureConfiguration.setOutputSignatureFormat(format);
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
                signatureConfiguration.setOutputDataEncoding(encoding);
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
                signatureConfiguration.setInputDataEncoding(encoding);
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
                connectionConfiguration.setSSLServerCertificateVerificationTo(Boolean
                        .parseBoolean(value));
                return null;
            }
        });
    }

    public void addInputURL(final String inputURL)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                signatureConfiguration.addInputURL(inputURL);
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
                signatureConfiguration.addOutputURL(outputURL);
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
                signatureConfiguration.setDniToCheckCertificateAgainst(dni);
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
                signatureConfiguration.addSignatureProperty(propertyName, propertyValue);
                return null;
            }
        });
    }

    public void setCertificate(final String certificateDN)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                PrivateKeyEntry privateKeyEntry = keyStoreManager
                        .getPrivateKeyEntryByDN(certificateDN);

                // TODO check usage with X509CertificateHandler
                // TODO check cert is valid

                signatureConfiguration.setPrivateKeyEntry(privateKeyEntry);

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
                try
                {
                    PrivateKeyEntry privateKeyEntry = signatureConfiguration.getPrivateKeyEntry();
                    Formatter formatter = new RawFormatter((X509Certificate) privateKeyEntry
                            .getCertificate(), privateKeyEntry.getPrivateKey(),
                            (Provider) new BouncyCastleProvider());
                }
                catch (SignatureException e)
                {
                    e.printStackTrace();
                }

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
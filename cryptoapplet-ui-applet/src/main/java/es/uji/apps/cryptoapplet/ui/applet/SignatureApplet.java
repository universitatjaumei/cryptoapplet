package es.uji.apps.cryptoapplet.ui.applet;

import java.io.ByteArrayInputStream;
import java.security.AccessController;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map.Entry;

import javax.swing.JApplet;

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.i18n.LabelManager;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
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
//    private LabelManager labelManager;

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
//            labelManager = new LabelManager();
            keyStoreManager = new KeyStoreManager(browser.getDetectedBrowser());

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

//    public void setLanguage(final String language)
//    {
//        AccessController.doPrivileged(new PrivilegedAction<Object>()
//        {
//            public Object run()
//            {
//                try
//                {
//                    labelManager = new LabelManager(new Locale(language));
//                }
//                catch (Exception e)
//                {
//                    log.error(e);
//                }
//
//                return null;
//            }
//        });
//    }

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

    public String getCertificates()
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                StringBuffer output = new StringBuffer();

                output.append("[");

                int length = keyStoreManager.getCertificates().size();
                int index = 0;

                for (X509Certificate certificate : keyStoreManager.getCertificates())
                {
                    output.append("{");
                    output.append("  dn: \"");
                    output.append(certificate.getSubjectDN().toString());
                    output.append("\", serial : ");
                    output.append(certificate.getSerialNumber());
                    output.append("}");

                    index++;

                    if (index != length)
                    {
                        output.append(",");
                    }
                }

                output.append("]");

                return output.toString();
            }
        });
    }

    public void setCertificate(final String certificateDN)
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                Entry<PrivateKeyEntry, Provider> privateKeyEntry = keyStoreManager
                        .getPrivateKeyEntryByDN(certificateDN);

                // TODO check usage with X509CertificateHandler
                // TODO check cert is valid

                signatureConfiguration.setPrivateKeyEntry(privateKeyEntry);

                return null;
            }
        });
    }

    public boolean sign()
    {
        return AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                try
                {
                    Entry<PrivateKeyEntry, Provider> privateKeyEntry = signatureConfiguration
                            .getPrivateKeyEntry();
                    Formatter formatter = new RawFormatter((X509Certificate) privateKeyEntry
                            .getKey().getCertificate(), privateKeyEntry.getKey().getPrivateKey(),
                            privateKeyEntry.getValue());

                    SignatureOptions signatureOptions = new SignatureOptions(configManager
                            .getConfiguration());
                    signatureOptions.setDataToSign(new ByteArrayInputStream("test".getBytes()));
                    SignatureResult signatureResult = formatter.format(signatureOptions);

                    return signatureResult.isValid();
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
}
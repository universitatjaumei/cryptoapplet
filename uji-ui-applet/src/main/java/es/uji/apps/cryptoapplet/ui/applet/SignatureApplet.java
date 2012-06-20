package es.uji.apps.cryptoapplet.ui.applet;

import java.security.AccessController;
import java.security.PrivilegedAction;

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

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.i18n.LabelManager;
import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;

@SuppressWarnings("serial")
public class SignatureApplet extends JApplet
{
    private Logger log = Logger.getLogger(SignatureApplet.class);

    private KeyStoreManager keyStoreManager;
    private JSCommands jsCommands;
    private SignatureConfiguration signatureConfiguration;
    private HttpConnectionConfiguration connectionConfiguration;

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
        this.signatureConfiguration = new SignatureConfiguration();
        this.connectionConfiguration = new HttpConnectionConfiguration();
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
        String baseURL = ".";

        if (this.getCodeBase() != null)
        {
            baseURL = this.getCodeBase().toString();
        }

        ConfigManager.getConfigurationInstance(baseURL);
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
        new MainWindow(keyStoreManager, jsCommands).show(signatureConfiguration);
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

    public void sign()
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
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
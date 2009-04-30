package es.uji.security.ui.applet;

import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import es.uji.security.crypto.TimeStampFactory;
import es.uji.security.keystore.IKeyStoreHelper;
import es.uji.security.util.ConfigHandler;

public class AppEnvironmentTester extends Thread
{

    private JFrame _jf = new JFrame();
    private AppHandler _apph;
    private JScrollPane _jsp = new JScrollPane();
    private JTextArea _jta = new JTextArea();
    private String appletTag, strerror = "", strwarn = "", inputUrl, outputUrl;
    int nerror = 0, ninfo = 0, nwarn = 0, delay = 1000;
    private Properties prop;

    private void caption(String str)
    {
        _jta.append("\nTesting: " + str + "\n");
        try
        {
            Thread.sleep(delay);
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();
        }
    }

    private void info(String str)
    {
        _jta.append("    [INFO]  " + str + "\n");
        ninfo++;
        try
        {
            Thread.sleep(delay);
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();
        }
    }

    private void warn(String str)
    {
        _jta.append("    [WARN]  " + str + "\n");
        strwarn += "    " + str + "\n";
        nwarn++;
        try
        {
            Thread.sleep(delay);
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();
        }
    }

    private void error(String str)
    {
        _jta.append("    [ERROR] " + str + "\n");
        strerror += "    " + str + "\n";
        nerror++;
        try
        {
            Thread.sleep(delay);
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();
        }
    }

    private void printSummary()
    {
        _jta.append("\n\nSUMMARY: ( " + ninfo + " info massages, " + nwarn + " warning messages "
                + nerror + " error messages )\n");

        if (nwarn != 0)
        {
            _jta.append("WARNING MESSAGES: \n");
            _jta.append(strwarn);
        }

        if (nerror != 0)
        {
            _jta.append("ERROR MESSAGES: \n");
            _jta.append(strerror);
        }
    }

    private void showAllowedCertificates(String property)
    {
        // Check certificates allowed to sign:
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ClassLoader cl = AppEnvironmentTester.class.getClassLoader();

            prop = ConfigHandler.getProperties();
            if (prop == null)
            {
                error("DDOC config file not found.");
                return;
            }

            // Get the CA certificate list
            String strinfo = "Certificates allowed to sign in this site: \n\n";
            Integer n = new Integer(prop.getProperty(property + "S"));
            Certificate CACert = null;

            for (int i = 1; i <= n; i++)
            {
                try
                {
                    CACert = cf.generateCertificate(cl.getResourceAsStream(prop.getProperty(
                            property + i).replaceFirst("jar://", "")));
                    strinfo += "        Issuer: "
                            + ((X509Certificate) CACert).getIssuerDN().toString()
                            + "\n        Subject:"
                            + ((X509Certificate) CACert).getSubjectDN().toString() + "\n\n";
                }
                catch (CertificateException e)
                {
                    error("Cannot parse certificate file  " + property + i + "="
                            + prop.getProperty(property + i) + " Exception: " + e.getMessage());
                }
            }
            info(strinfo);
        }
        catch (CertificateException e)
        {
            error("Unable to instantiate CertificateFactory Exception: " + e.getMessage());
        }

    }

    public void testTSA()
    {

        String tst = new String("01234567890123456789");

        try
        {
            caption(" TSA (Time Stamp Authority)");

            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.setCertReq(false);

            byte[] hash = tst.getBytes();

            prop = ConfigHandler.getProperties();
            if (prop == null)
            {
                error("DDOC config file not found.");
                return;
            }
            String tsaUrl = prop.getProperty("DIGIDOC_TSA1_URL");
            byte[] asn1Resp = TimeStampFactory.getTimeStamp(tsaUrl, hash);

            if (asn1Resp == null)
            {
                error("Timeout getting the timestamp.");
            }

            TimeStampResponse tsr = new TimeStampResponse(asn1Resp);
            TimeStampToken ttk = tsr.getTimeStampToken();

            if (ttk == null)
            {
                error("Cannot get TSARESPONSE");
            }

            TimeStampTokenInfo tstki = ttk.getTimeStampInfo();
            if (tstki == null)
            {
                error("Cannot get TimeStampInfo");
            }

            byte[] msgdig = tstki.getMessageImprintDigest();
            if (msgdig == null)
            {
                error("Cannot get MessageImprintDigest");
            }

            String dig = new String(msgdig);

            if (new String(msgdig).equals(tst))
            {
                info("Message digest got ok : " + dig);
                info("Timestamped time for the digest: " + tstki.getGenTime());
            }
            else
            {
                error("Message digests does not match");
            }
        }
        catch (Exception e)
        {
            error("Calculating timestamp, Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void testOCSP()
    {
        caption("OCSP");
        prop = ConfigHandler.getProperties();
        if (prop == null)
        {
            error("DDOC config file not found.");
            return;
        }

        Integer n = new Integer(prop.getProperty("DIGIDOC_OCSP_RESPONDER_COUNT"));

        for (int i = 1; i <= n; i++)
        {
            try
            {
                testConnect(new URL(prop.getProperty("DIGIDOC_OCSP_RESPONDER_URL" + i)));
            }
            catch (Exception e)
            {
                error("In OCSP test Exception: " + e.getMessage());
            }
        }
    }

    private void testConnect(URL url)
    {
        try
        {
            HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();

            urlConn.setConnectTimeout(10000);
            urlConn.setReadTimeout(10000);

            urlConn.setRequestMethod("GET");
            urlConn.setDoOutput(true);
            urlConn.setDoInput(true);

            if (urlConn.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                error("Connecting with " + url.toString() + " . Error= "
                        + urlConn.getResponseCode());
            }
            else
            {
                info("Connection to " + url.toString() + " OK");
            }
        }
        catch (Exception e)
        {
            error("Connection to " + url.toString() + " has thrown Exception: " + e.getMessage());
        }
    }

    private void testJavaVersion()
    {
        caption("Version");
        String version = _apph.getSignatureApplet().getJavaVersion();
        info("Got java version: " + version);
        if (!(version.startsWith("1.6") || version.startsWith("1.5") || version.startsWith("1.7")))
        {

            error("Java version must be >= 1.5");
        }
        else
        {
            info("Java version compatible with the applet!");
        }
    }

    private void testAppletTag()
    {
        caption("Applet Tag");
        URL codebase = _apph.getSignatureApplet().getCodeBase();

        info("Got codebase: " + codebase.toString());
        testConnect(codebase);

        String loweredTag = this.appletTag.toLowerCase();

        int ini = loweredTag.indexOf("mayscript");
        if (ini == -1)
        {
            warn("mayscript tag not found, the applet could not work on firefox.");
            return;
        }

        ini = loweredTag.indexOf("archive");
        if (ini == -1)
        {
            error("Cannot locate archive attribute in applet tag.");
            return;
        }

        int i = loweredTag.indexOf("\"", ini);

        if (i == -1)
            i = loweredTag.indexOf("'", ini);

        if (i == -1)
        {
            error("Unable to find the stating \" or ' at archive attribute.");
            return;
        }

        int end = loweredTag.indexOf("\"", i + 1);
        if (end == -1)
            end = loweredTag.indexOf("'", i + 1);
        if (end == -1)
        {
            error("Unable to find the closing \" or ' at archive attribute.");
            return;
        }

        String aux = this.appletTag.substring(ini, end);
        aux = aux.replaceFirst("archive[ ]*=[ ]*['\"]", "");
        aux = aux.replaceAll("[\r\n]", "");

        String items[] = aux.split(",");
        for (i = 0; i < items.length; i++)
        {
            try
            {
                testConnect(new URL(codebase.toString() + items[i]));
            }
            catch (MalformedURLException e)
            {
                error("Cannot check " + codebase.toString() + items[i]
                        + " has thrown MalformedURLException");
            }
        }
    }

    private void testSignatureOutputFormat()
    {
        caption("SignatureOutputFormat");

        String format = _apph.getSignatureOutputFormat();
        String lowerTag = this.appletTag.toLowerCase();

        info("signatureOutputFormat set to: " + format);

        if (_apph.getformatImplMap().get(format) == null)
        {
            error("Invalid output format " + format);
            return;
        }

        // Check dependencies.
        String gendeps[] = { "bcprov", "jakarta", "ujiutils", "ujiapplet", "ujicrypto", "ujiconfig" };
        for (String aux : gendeps)
        {
            if (lowerTag.indexOf(aux) == -1)
            {
                warn(aux
                        + ".*  not found and it is needed by all signature formats, make sure you have included it with another name.");
            }
        }

        if (lowerTag.indexOf("jakarta") == -1)
        {
            warn("jakarta.* not found and it is needed by all signature formats, make sure you have included it with another name.");
        }

        if (format.equals("CMS") | format.equals("CMS_HASH"))
        {
            if (lowerTag.indexOf("bcmail") == -1)
            {
                warn("bcmail.* not found and it is needed by " + format + " singature format");
            }
        }
        else if (format.equals("XADES") | format.equals("XADES_COSIGN"))
        {
            String deps[] = { "bcmail", "bctsp", "xalan", "xmlsec", "myxmlsec" };
            for (String aux : deps)
            {
                if (lowerTag.indexOf(aux) == -1)
                {
                    warn(aux + ".* not found and it is needed by " + format + " singature format");
                }
            }
            showAllowedCertificates("DIGIDOC_CA_CERT");
            testTSA();
        }
        else if (format.equals("PDF"))
        {
            if (lowerTag.indexOf("itext") == -1)
            {
                warn("itext.* not found and it is needed by " + format + " singature format");
            }

            showAllowedCertificates("PDFSIG_CA_CERT");
        }
    }

    private void testCertificates()
    {
        try
        {
            caption("User Certificates, you must check that the Issuer of your certificate is like any\nof the Subjects in allowed certificates section");
            String strinfo = "User Certificates detected: \n\n";
            for (IKeyStoreHelper ikh : _apph.getKeyStoreTable().values())
            {
                for (Certificate c : ikh.getUserCertificates())
                {
                    strinfo += "        Issuer:" + ((X509Certificate) c).getIssuerDN().toString()
                            + "\n        Subject:" + ((X509Certificate) c).getSubjectDN() + "\n\n";
                }
            }
            info(strinfo);
        }
        catch (Exception e)
        {
            error("Cannot get user certificates. Exception: " + e.getMessage());
        }

    }

    private void testInputOutput()
    {
        caption("Testing source input and source output");
        if (inputUrl != null && !inputUrl.equals(""))
        {
            try
            {
                testConnect(new URL(inputUrl));
            }
            catch (Exception e)
            {
                error("Malformed URL: " + inputUrl);
            }
        }
        if (outputUrl != null && !outputUrl.equals(""))
        {
            try
            {
                testConnect(new URL(outputUrl));
            }
            catch (Exception e)
            {
                error("Malformed URL: " + inputUrl);
            }
        }
    }

    public void setAppletHandler(AppHandler apph)
    {
        this._apph = apph;
    }

    public void setup(String appletTag, String inputUrl, String outputUrl)
    {
        this.appletTag = appletTag;
        this.inputUrl = inputUrl;
        this.outputUrl = outputUrl;
    }

    public void run()
    {
        Toolkit toolkit = Toolkit.getDefaultToolkit();
        int _height = toolkit.getScreenSize().height;
        int _width = toolkit.getScreenSize().width;

        _jta.setEditable(false);
        _jta.append("Resultados de los tests:\n");

        _jsp.setBounds(new Rectangle(9, 28, 558, 173));
        _jsp.setViewportView(_jta);
        _jsp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        _jsp.getVerticalScrollBar().addAdjustmentListener(new AdjustmentListener()
        {
            public void adjustmentValueChanged(AdjustmentEvent e)
            {
                _jta.select(_jta.getHeight() + 10000, 0);
                _jsp.updateUI();
            }
        });

        _jsp.getHorizontalScrollBar().addAdjustmentListener(new AdjustmentListener()
        {
            public void adjustmentValueChanged(AdjustmentEvent e)
            {
                _jsp.updateUI();
            }
        });

        _jf.setLocation(_width / 2 - 582 / 2, _height / 2 - 518 / 2);

        _jf.setTitle("Application Test");
        _jf.setSize(new Dimension(700, 400));
        // _jf.setBounds(new Rectangle(9, 28, 558, 173));

        _jf.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        _jf.setContentPane(_jsp);
        _jf.setVisible(true);

        // Lets go with the tests
        testJavaVersion();
        testAppletTag();
        testInputOutput();
        testSignatureOutputFormat();
        testCertificates();
        testOCSP();
        printSummary();

    }
}

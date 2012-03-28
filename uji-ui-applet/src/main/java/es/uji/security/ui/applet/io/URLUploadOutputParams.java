package es.uji.security.ui.applet.io;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import es.uji.security.crypto.config.OperatingSystemUtils;
import es.uji.security.ui.applet.SignatureApplet;

public class URLUploadOutputParams extends AbstractData implements OutputParams
{
    private Logger log = Logger.getLogger(URLUploadOutputParams.class);

    private static final String NEWLINE = "\r\n";
    private static final String PREFIX = "--";

    private String[] urls = null;
    private int current = 0;
    private boolean signOkInvoked = false;
    private int _count = 1;
    private int outputcount = 0;
    private int conn_timeout = 10000;
    private int read_timeout = 60000;
    private String postVariable = "content";

    public URLUploadOutputParams(String[] urls)
    {
        this(urls, "content");
    }

    public URLUploadOutputParams(String[] urls, String postVariable)
    {
        log.debug("Parametro URLS: " + urls);
        log.debug("Parametro postVariable: " + postVariable);

        this.urls = urls;
        this.postVariable = postVariable;
    }

    public void setOutputCount(int oCount)
    {
        this.outputcount = oCount;
    }

    public void setSignData(InputStream is) throws IOException
    {
        String cookies = "";

        // Try to obtain and configure Cookies

        try
        {
            log.debug("Recover JavaScript member: document");

            // TODO: How todo this call?
            // JSObject document = (JSObject) JSCommands.getWindow().getMember("document");
            // cookies = (String) document.getMember("cookie");

            log.debug("Cookies: " + cookies);
        }
        catch (Exception e)
        {
            log.debug("Cookies can not be obtained", e);
        }

        String urlOk = this.urls[current];

        if (this.urls[current].indexOf('?') > -1)
        {
            urlOk = this.urls[current].substring(0, this.urls[current].indexOf('?'));
        }
        else
        {
            urlOk = this.urls[current];
        }

        log.debug("Uploading data to " + urlOk + ", with post parameter variable " + postVariable);

        URL url = new URL(urlOk);

        HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();

        urlConn.setConnectTimeout(conn_timeout);
        urlConn.setReadTimeout(read_timeout);

        urlConn.setRequestMethod("POST");

        String Boundary = ((Math.random() * 1000000000000l) + 9000000000000l) + "";

        urlConn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + Boundary);
        urlConn.setRequestProperty("Connection", "Keep-Alive");
        urlConn.setRequestProperty("Cache-Control", "no-cache");
        urlConn.setRequestProperty("Cookie", "");

        urlConn.setDoOutput(true);
        urlConn.setDoInput(true);
        urlConn.setAllowUserInteraction(false);
        urlConn.setUseCaches(false);
        urlConn.setChunkedStreamingMode(1024);

        DataOutputStream out = new DataOutputStream(urlConn.getOutputStream());

        String str = PREFIX + Boundary + NEWLINE + "Content-Disposition:form-data;name=\"item\""
                + NEWLINE + NEWLINE + URLEncoder.encode("" + _count, "ISO-8859-1") + NEWLINE;

        out.writeBytes(str);

        StringTokenizer strTok = new StringTokenizer(
                this.urls[current].substring(this.urls[current].indexOf('?') + 1), "&");

        while (strTok.hasMoreTokens())
        {
            String strAux = strTok.nextToken();
            log.debug("PROCESANDO TOKEN: " + strAux);

            if (strAux.indexOf("=") > -1)
            {
                String var = strAux.substring(0, strAux.indexOf("="));
                String value = strAux.substring(strAux.indexOf("=") + 1);
                log.debug("ENVIANDO EN EL UPLOAD: " + var + "=" + value);

                str = PREFIX + Boundary + NEWLINE + "Content-Disposition:form-data;name=\"" + var
                        + "\"" + NEWLINE + NEWLINE + URLEncoder.encode(value, "ISO-8859-1")
                        + NEWLINE;
                out.writeBytes(str);
            }
        }

        out.flush();

        int contadorPartes = 0;

        log.debug("ENVIANDO EL FICHERO FIRMADO ");

        String strPostFile = PREFIX + Boundary + NEWLINE + "Content-Disposition:form-data;name=\""
                + postVariable + "\";filename=\"" + postVariable + ".pdf\"" + NEWLINE
                + "Content-Type: application/pdf'" + NEWLINE + NEWLINE;
        out.writeBytes((strPostFile));
        out.flush();

        byte[] buffer = new byte[1024];
        int length = 0;

        while ((length = is.read(buffer)) != -1)
        {
            out.write(buffer, 0, length);
        }

        try
        {
            is.close();
            new File(OperatingSystemUtils.getSystemTmpDir() + "/signature.xsig").delete();
        }
        catch (Exception e)
        {
        }

        out.writeBytes(NEWLINE + PREFIX + Boundary);
        out.flush();
        out.close();

        if (urlConn.getResponseCode() >= 400)
        {
            log.error("Error en el upload: " + urlConn.getResponseCode());

            throw new IOException("Error en el upload: " + urlConn.getResponseCode());
        }

        _count++;
        current++;
    }

    public void setSignFormat(SignatureApplet base, byte[] signFormat)
    {
    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
    }

    public void signOk()
    {
        if (!signOkInvoked)
        {
            log.debug("Call JavaScript method: onSignOk");

            // TODO: How todo this call?
            // JSCommands.getWindow().call("onSignOk", new String[] { "" });
        }
    }

    public void flush()
    {
        _count = 1;
        current = 0;
    }
}

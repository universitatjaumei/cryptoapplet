package es.uji.apps.cryptoapplet.ui.service;

import es.uji.apps.cryptoapplet.ui.service.commands.Command;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

public class Request
{
    private final String requestText;
    private final URL url;

    public Request(InputStream inputStream) throws IOException
    {
        this.requestText = readMessage(inputStream);

        String queryPath = extractUrlFromRequest();
        this.url = new URL("http://localhost" + queryPath);
    }

    public String getCallBack() throws MalformedURLException
    {
        return url.getQuery().split("&")[0].split("=")[1];
    }

    public Command getCommand() throws MalformedURLException
    {
        return Command.valueOf(url.getPath().split("/")[2]);
    }

    public Map<String, String> getQueryParams() throws UnsupportedEncodingException
    {
        Map<String, String> params = new HashMap<String, String>();

        for (String param : this.url.getQuery().split("&"))
        {
            String[] values = param.split("=");
            params.put(values[0], URLDecoder.decode(values[1], "UTF-8"));
        }

        return params;
    }

    public boolean isValid()
    {
        return requestText != null && requestText.length() > 0;
    }

    public byte[] getData() throws Exception
    {
        Map<String, String> params = getQueryParams();
        String inputUrl = params.get("inputUrl");

        URL url = new URL(inputUrl);
        URLConnection uc = url.openConnection();

        uc.setConnectTimeout(10000);
        uc.setReadTimeout(10000);

        uc.connect();

        return StreamUtils.inputStreamToByteArray(uc.getInputStream());
    }

    private String extractUrlFromRequest()
    {
        String result = "";
        String[] urlFragments = requestText.split("\\ ");

        if (urlFragments != null && urlFragments.length > 1)
        {
            result = urlFragments[1];
        }

        return result;
    }

    private String readMessage(InputStream inputStream) throws IOException
    {
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                inputStream));

        StringBuffer buffer = new StringBuffer();

        while (true)
        {
            int ch = reader.read();

            if ((ch < 0) || (ch == '\n'))
            {
                break;
            }

            buffer.append((char) ch);
        }

        return buffer.toString();
    }
}

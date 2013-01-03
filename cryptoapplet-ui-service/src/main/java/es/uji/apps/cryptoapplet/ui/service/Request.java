package es.uji.apps.cryptoapplet.ui.service;

import es.uji.apps.cryptoapplet.ui.service.commands.Command;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;

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

    public boolean isInvalid()
    {
        return requestText == null || requestText.length() == 0;
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

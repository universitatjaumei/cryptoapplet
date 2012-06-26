package es.uji.apps.cryptoapplet.crypto.pdf;

import java.util.Map;
import java.util.StringTokenizer;

public class PatternParser
{
    private String pattern;

    public PatternParser(String pattern)
    {
        this.pattern = pattern;
    }

    public String parse(Map<String, String> bindValues)
    {
        StringTokenizer tokenizer = new StringTokenizer(pattern);
        StringBuilder result = new StringBuilder();
        String currentToken;

        while (tokenizer.hasMoreTokens())
        {
            currentToken = tokenizer.nextToken();

            if (bindValues.containsKey(currentToken))
            {
                result.append(bindValues.get(currentToken)).append(" ");
            }
            else
            {
                result.append(currentToken).append(" ");
            }

        }

        return result.toString().trim();
    }
}

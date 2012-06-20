package es.uji.apps.cryptoapplet.crypto.pdf;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.Configuration;
import es.uji.apps.cryptoapplet.config.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;

public class ConfigurationAdapter
{
    private SignatureOptions signatureOptions;
    private Formatter formatter;

    public ConfigurationAdapter(SignatureOptions signatureOptions)
    {
        this.signatureOptions = signatureOptions;

        Configuration conf = ConfigManager.getConfigurationInstance();

        for (Formatter formatter : conf.getFormatterRegistry().getFormatters())
        {
            if ("pdf".equalsIgnoreCase(formatter.getId().toLowerCase()))
            {
                this.formatter = formatter;
                break;
            }
        }

        if (this.formatter == null)
        {
            throw new IllegalArgumentException("PDF formatter not found");
        }
    }

    public String getProperty(String value, String defaultValue)
    {
        if (value != null && !value.isEmpty())
        {
            return value;
        }
        else
        {
            return defaultValue;
        }
    }

    public String getReason()
    {
        return getProperty(formatter.getConfiguration().get("reason"),
                "CryptoApplet digital signatures");
    }

    public String getLocation()
    {
        return getProperty(formatter.getConfiguration().get("location"), "Spain");
    }

    public String getContact()
    {
        return getProperty(formatter.getConfiguration().get("contact"), "Universitat Jaume I");
    }

    public boolean isTimestamping()
    {
        return (formatter.getTsaId() != null && !formatter.getTsaId().isEmpty());
    }

    public String getTsaURL()
    {
        return null;
        // TODO Extract correct TSA url
        // TODO considerar el SignatureOptions como precedencia de operadores
        // if (signatureOptions.getTsaURL() != null && signatureOptions.getTsaURL().length() > 0)
        // {
        // return signatureOptions.getTsaURL();
        // }
        // else
        // {
        // return conf.getProperty("PDFSIG_TSA_URL", "http://tss.accv.es:8318/tsa");
        // }
    }

    public boolean isVisibleSignature()
    {
        String visibleSignature = getProperty(
                formatter.getConfiguration().get("signature.visible"), "true");
        return (visibleSignature != null && "true".equals(visibleSignature));
    }

    public String getVisibleSignatureType()
    {
        return getProperty(formatter.getConfiguration().get("signature.type"),
                "GRAPHIC_AND_DESCRIPTION");
    }

    public int getVisibleAreaX()
    {
        return Integer.parseInt(getProperty(formatter.getConfiguration().get("signature.x"), "0"));
    }

    public int getVisibleAreaY()
    {
        return Integer
                .parseInt(getProperty(formatter.getConfiguration().get("signature.y"), "830"));
    }

    public int getVisibleAreaX2()
    {
        return Integer
                .parseInt(getProperty(formatter.getConfiguration().get("signature.x2"), "180"));
    }

    public int getVisibleAreaY2()
    {
        return Integer
                .parseInt(getProperty(formatter.getConfiguration().get("signature.y2"), "785"));
    }

    public int getVisibleAreaPage()
    {
        return Integer
                .parseInt(getProperty(formatter.getConfiguration().get("signature.page"), "1"));
    }

    public int getVisibleAreaTextSize()
    {
        return Integer.parseInt(getProperty(formatter.getConfiguration().get("signature.textSize"),
                "8"));
    }

    public String getVisibleAreaImgFile()
    {
        return getProperty(formatter.getConfiguration().get("signature.imgFile"), "uji.jpg");
    }

    public String getVisibleAreaRepeatAxis()
    {
        return getProperty(formatter.getConfiguration().get("signature.repeatAxis"), "X");
    }

    public String getVisibleAreaTextPattern()
    {
        return getProperty(formatter.getConfiguration().get("signature.textPattern"), "");
    }
}

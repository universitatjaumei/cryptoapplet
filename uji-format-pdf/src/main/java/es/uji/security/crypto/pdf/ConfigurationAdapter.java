package es.uji.security.crypto.pdf;

import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.config.ConfigManager;

public class ConfigurationAdapter
{
    private SignatureOptions signatureOptions;
    private ConfigManager conf = ConfigManager.getInstance();

    public ConfigurationAdapter(SignatureOptions signatureOptions)
    {
        this.signatureOptions = signatureOptions;
    }

    public String getReason()
    {
        if (signatureOptions.getReason() != null && signatureOptions.getReason().length() > 0)
        {
            return signatureOptions.getReason();
        }
        else
        {
            return conf.getProperty("PDFSIG_REASON", "CryptoApplet digital signatures");
        }
    }

    public String getLocation()
    {
        if (signatureOptions.getLocation() != null && signatureOptions.getLocation().length() > 0)
        {
            return signatureOptions.getLocation();
        }
        else
        {
            return conf.getProperty("PDFSIG_LOCATION", "Spain");
        }
    }

    public String getContact()
    {
        if (signatureOptions.getContact() != null && signatureOptions.getContact().length() > 0)
        {
            return signatureOptions.getContact();
        }
        else
        {
            return conf.getProperty("PDFSIG_CONTACT", "Universitat Jaume I");
        }
    }

    public boolean isTimestamping()
    {
        if (signatureOptions.isTimestamping() != null)
        {
            return signatureOptions.isTimestamping();
        }
        else
        {
            String config = conf.getProperty("PDFSIG_TIMESTAMPING", "true");
            return (config.equals("true"));
        }
    }

    public String getTsaURL()
    {
        if (signatureOptions.getTsaURL() != null && signatureOptions.getTsaURL().length() > 0)
        {
            return signatureOptions.getTsaURL();
        }
        else
        {
            return conf.getProperty("PDFSIG_TSA_URL", "http://tss.accv.es:8318/tsa");
        }
    }

    public boolean isVisibleSignature()
    {
        if (signatureOptions.isVisibleSignature() != null)
        {
            return signatureOptions.isVisibleSignature();
        }
        else
        {
            String config = conf.getProperty("PDFSIG_VISIBLE_SIGNATURE", "true");
            return (config.equals("true"));
        }
    }

    public String getVisibleSignatureType()
    {
        if (signatureOptions.getVisibleSignatureType() != null
                && signatureOptions.getVisibleSignatureType().length() > 0)
        {
            return signatureOptions.getVisibleSignatureType();
        }
        else
        {
            return conf.getProperty("PDFSIG_VISIBLE_SIGNATURE_TYPE", "GRAPHIC_AND_DESCRIPTION");
        }
    }

    public int getVisibleAreaX()
    {
        if (signatureOptions.getVisibleAreaX() != null)
        {
            return signatureOptions.getVisibleAreaX();
        }
        else
        {
            return conf.getIntProperty("PDFSIG_VISIBLE_AREA_X", 0);
        }
    }

    public int getVisibleAreaY()
    {
        if (signatureOptions.getVisibleAreaY() != null)
        {
            return signatureOptions.getVisibleAreaY();
        }
        else
        {
            return conf.getIntProperty("PDFSIG_VISIBLE_AREA_Y", 830);
        }
    }

    public int getVisibleAreaX2()
    {
        if (signatureOptions.getVisibleAreaX2() != null)
        {
            return signatureOptions.getVisibleAreaX2();
        }
        else
        {
            return conf.getIntProperty("PDFSIG_VISIBLE_AREA_X2", 180);
        }
    }

    public int getVisibleAreaY2()
    {
        if (signatureOptions.getVisibleAreaY2() != null)
        {
            return signatureOptions.getVisibleAreaY2();
        }
        else
        {
            return conf.getIntProperty("PDFSIG_VISIBLE_AREA_Y2", 785);
        }
    }

    public int getVisibleAreaPage()
    {
        if (signatureOptions.getVisibleAreaPage() != null)
        {
            return signatureOptions.getVisibleAreaPage();
        }
        else
        {
            return conf.getIntProperty("PDFSIG_VISIBLE_AREA_PAGE", 1);
        }
    }

    public int getVisibleAreaTextSize()
    {
        if (signatureOptions.getVisibleAreaTextSize() != null)
        {
            return signatureOptions.getVisibleAreaTextSize();
        }
        else
        {
            return conf.getIntProperty("PDFSIG_VISIBLE_AREA_TEXT_SIZE", 8);
        }
    }

    public String getVisibleAreaImgFile()
    {
        if (signatureOptions.getVisibleAreaImgFile() != null
                && signatureOptions.getVisibleAreaImgFile().length() > 0)
        {
            return signatureOptions.getVisibleAreaImgFile();
        }
        else
        {
            return conf.getProperty("PDFSIG_VISIBLE_AREA_IMGFILE", "uji.jpg");
        }
    }

    public String getVisibleAreaRepeatAxis()
    {
        if (signatureOptions.getVisibleAreaRepeatAxis() != null
                && signatureOptions.getVisibleAreaRepeatAxis().length() > 0)
        {
            return signatureOptions.getVisibleAreaRepeatAxis();
        }
        else
        {
            return conf.getProperty("PDFSIG_VISIBLE_AREA_REPEAT_AXIS", "X");
        }
    }

    public String getVisibleAreaTextPattern()
    {
        if (signatureOptions.getVisibleAreaTextPattern() != null
                && signatureOptions.getVisibleAreaTextPattern().length() > 0)
        {
            return signatureOptions.getVisibleAreaTextPattern();
        }
        else
        {
            return conf.getProperty("PDFSIG_VISIBLE_AREA_TEXT_PATTERN", "");
        }
    }
}

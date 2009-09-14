package es.uji.security.crypto.openxades;

import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.factory.CRLFactory;
import es.uji.security.crypto.openxades.digidoc.factory.CanonicalizationFactory;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.factory.NotaryFactory;
import es.uji.security.crypto.openxades.digidoc.factory.SignatureFactory;
import es.uji.security.crypto.openxades.digidoc.factory.TimestampFactory;

public class ConfigHandler
{
    private static ConfigManager conf = ConfigManager.getInstance();
    private static DigiDocFactory digidocFactory;
    private static CanonicalizationFactory canonicalizationFactory;
    private static NotaryFactory notaryFactory;
    private static SignatureFactory signatureFactory;
    private static CRLFactory crlFactory;
    private static TimestampFactory timestampFactory;

    public static DigiDocFactory getDigiDocFactory() throws DigiDocException
    {
        try
        {
            if (digidocFactory == null)
            {
                digidocFactory = (DigiDocFactory) Class.forName(
                        conf.getProperty("DIGIDOC_FACTORY_IMPL")).newInstance();
                digidocFactory.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
        }

        return digidocFactory;
    }

    public static CanonicalizationFactory getCanonicalizationFactory() throws DigiDocException
    {
        try
        {
            if (canonicalizationFactory == null)
            {
                canonicalizationFactory = (CanonicalizationFactory) Class.forName(
                        conf.getProperty("CANONICALIZATION_FACTORY_IMPL")).newInstance();
                canonicalizationFactory.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_FAC_INIT);
        }

        return canonicalizationFactory;
    }

    public static NotaryFactory getNotaryFactory() throws DigiDocException
    {
        try
        {
            if (notaryFactory == null)
            {
                notaryFactory = (NotaryFactory) Class.forName(
                        conf.getProperty("DIGIDOC_NOTARY_IMPL")).newInstance();
                notaryFactory.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        }

        return notaryFactory;
    }

    public static SignatureFactory getSignatureFactory() throws DigiDocException
    {
        try
        {
            if (signatureFactory == null)
            {
                signatureFactory = (SignatureFactory) Class.forName(
                        conf.getProperty("DIGIDOC_SIGN_IMPL")).newInstance();
                signatureFactory.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }

        return signatureFactory;
    }

    public static CRLFactory getCRLFactory() throws DigiDocException
    {
        try
        {
            if (crlFactory == null)
            {
                crlFactory = (CRLFactory) Class.forName(conf.getProperty("CRL_FACTORY_IMPL"))
                        .newInstance();
                crlFactory.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL_FAC);
        }

        return crlFactory;
    }

    public static TimestampFactory getTimestampFactory() throws DigiDocException
    {
        try
        {
            if (timestampFactory == null)
            {
                timestampFactory = (TimestampFactory) Class.forName(conf.getProperty("DIGIDOC_TIMESTAMP_IMPL"))
                        .newInstance();
                timestampFactory.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_TIMESTAMP_FAC_INIT);
        }
        
        return timestampFactory;

    }
}
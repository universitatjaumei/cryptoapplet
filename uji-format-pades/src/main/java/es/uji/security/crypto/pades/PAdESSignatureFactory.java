package es.uji.security.crypto.pades;

import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.afirma.signers.tsp.pkcs7.TsaParams;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.OS;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class PAdESSignatureFactory implements ISignFormatProvider
{
    private Logger log = Logger.getLogger(PAdESSignatureFactory.class);

    private PrivateKey privateKey;

    private ConfigManager conf = ConfigManager.getInstance();
    private String tsaURL;

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception {
        log.debug("Init PAdES signature configuration");

        byte[] datos = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate certificate = signatureOptions.getCertificate();
        this.privateKey = signatureOptions.getPrivateKey();

        AOSigner signer = new AOPDFSigner();

        Properties extraProperties = new Properties();
        extraProperties.put("tsaURL", "http://psis.catcert.net/psis/catcert/tsp");
        extraProperties.put("tsType", TsaParams.TS_SIGN);

        final byte[] result = signer.sign(
                datos,
                AOSignConstants.SIGN_ALGORITHM_SHA1WITHRSA,
                this.privateKey,
                new Certificate[]{
                        certificate,
                        findCACertificateFor(certificate)
                },
                extraProperties
        );

        SignatureResult signatureResult = new SignatureResult();
        signatureResult.setValid(true);
        signatureResult.setSignatureData(new ByteArrayInputStream(result));

        return signatureResult;
    }

    private Certificate findCACertificateFor(Certificate cert)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException
    {
        Integer n = new Integer(conf.getProperty("DIGIDOC_CA_CERTS"));
        Certificate CACert = null;

        for (int i = 1; i <= n; i++)
        {
            CACert = ConfigManager.readCertificate(conf.getProperty("DIGIDOC_CA_CERT" + i));

            try
            {
                cert.verify(CACert.getPublicKey());
                break;
            }
            catch (SignatureException e)
            {
                CACert = null;
            }
        }

        return CACert;
    }
}
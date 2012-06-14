package es.uji.apps.cryptoapplet.crypto.raw;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.apps.cryptoapplet.config.i18n.LabelManager;
import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class RawFormatter implements Formatter
{
    private Logger log = Logger.getLogger(RawFormatter.class);

    @Override
    public SignatureResult format(SignatureOptions signatureOptions)
            throws CryptoAppletCoreException
    {
        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate certificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();
        Provider provider = signatureOptions.getProvider();

        log.info("Init SHA1withRSA signature");

        SignatureResult signatureResult = new SignatureResult();

        try
        {
            Signature rsa = Signature.getInstance("SHA1withRSA", provider);

            if (certificate == null)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERR_RAW_NOCERT"));

                log.error(LabelManager.get("ERR_RAW_NOCERT"));

                return signatureResult;
            }

            if (privateKey == null)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERR_RAW_NOKEY"));

                log.error(LabelManager.get("ERR_RAW_NOCERT"));

                return signatureResult;
            }

            rsa.initSign(privateKey);
            rsa.update(data);

            byte[] res = rsa.sign();

            // Verification

            log.info("Trying to verify signed data");

            Signature rsa_vfy = Signature.getInstance("SHA1withRSA", new BouncyCastleProvider());
            rsa_vfy.initVerify(certificate.getPublicKey());
            rsa_vfy.update(data);

            if (res == null)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_RAW_SIGNATURE"));

                log.info(LabelManager.get("ERROR_RAW_SIGNATURE"));
            }
            else
            {
                signatureResult.setValid(true);
                signatureResult.setSignatureData(new ByteArrayInputStream(res));

                log.info("Signature verified");
            }
        }
        catch (Exception e)
        {
            throw new CryptoAppletCoreException(e);
        }

        return signatureResult;
    }
}
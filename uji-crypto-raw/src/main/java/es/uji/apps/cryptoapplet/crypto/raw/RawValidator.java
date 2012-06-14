package es.uji.apps.cryptoapplet.crypto.raw;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import es.uji.apps.cryptoapplet.crypto.ValidationResult;

public class RawValidator
{
    public ValidationResult verify(byte[] data, byte[] signature, X509Certificate caCertificate,
            Provider provider) throws CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException
    {
        Signature rsa_vfy = Signature.getInstance("SHA1withRSA", provider);
        rsa_vfy.initVerify(caCertificate.getPublicKey());
        rsa_vfy.update(data);

        ValidationResult verificationDetails = new ValidationResult();
        verificationDetails.setValid(rsa_vfy.verify(signature));

        if (!verificationDetails.isValid())
        {
            verificationDetails.addError("RAW signature can not be verified");
        }

        return verificationDetails;
    }
}
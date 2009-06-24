package es.uji.security.crypto.raw;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class RawSignatureVerifier
{
    public boolean verify(byte[] data, byte[] signature, X509Certificate caCertificate)
            throws CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException
    {
        Signature rsa_vfy = Signature.getInstance("SHA1withRSA");
        rsa_vfy.initVerify(caCertificate.getPublicKey());
        rsa_vfy.update(data);

        return rsa_vfy.verify(signature);
    }
}
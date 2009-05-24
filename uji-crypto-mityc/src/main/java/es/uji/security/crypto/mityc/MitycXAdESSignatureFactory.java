package es.uji.security.crypto.mityc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;

public class MitycXAdESSignatureFactory implements ISignFormatProvider
{    
    public byte[] formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        byte[] data = signatureOptions.getToSignByteArray();
        X509Certificate signerCertificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();
        
        Configuracion configuracion = new Configuracion();
        configuracion.cargarConfiguracion();

        FirmaXML sxml = new FirmaXML(configuracion);
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        sxml.signFile(signerCertificate.getSerialNumber(), signerCertificate.getIssuerDN().toString(), 
                signerCertificate, new ByteArrayInputStream(data), null, "Certificate1,<root>", 
                privateKey, bos, false);
        
        return bos.toByteArray();
    }

    public String getError()
    {
        return null;
    }
}
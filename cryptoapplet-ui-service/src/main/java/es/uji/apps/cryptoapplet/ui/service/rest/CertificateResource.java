package es.uji.apps.cryptoapplet.ui.service.rest;

import com.sun.jersey.api.json.JSONWithPadding;
import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;
import es.uji.apps.cryptoapplet.ui.service.model.Certificate;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Path("certificates")
public class CertificateResource
{
    @GET
    @Produces("application/javascript")
    public JSONWithPadding certificates(@QueryParam("callback") String callback) throws GeneralSecurityException, IOException
    {
        List<Certificate> certificates = new ArrayList<Certificate>();

        KeyStoreManager keyStoreManager = new KeyStoreManager();

        for (X509Certificate storedCertificate : keyStoreManager.getCertificates())
        {
            String dn = storedCertificate.getSubjectDN().toString();
            BigInteger serial = storedCertificate.getSerialNumber();

            certificates.add(new Certificate(dn, serial));
        }

        return new JSONWithPadding(certificates, callback);
    }
}
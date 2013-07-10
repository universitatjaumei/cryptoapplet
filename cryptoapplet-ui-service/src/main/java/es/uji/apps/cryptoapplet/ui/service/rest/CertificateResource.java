package es.uji.apps.cryptoapplet.ui.service.rest;

import com.sun.jersey.api.json.JSONWithPadding;
import es.uji.apps.cryptoapplet.ui.service.model.Certificate;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Path("certificates")
public class CertificateResource extends AbstractBaseResource
{
    public CertificateResource() throws GeneralSecurityException, IOException
    {
        super();
    }

    @GET
    @Produces("application/javascript")
    public JSONWithPadding certificates(@QueryParam("callback") String callback)
    {
        List<Certificate> certificates = new ArrayList<Certificate>();

        for (X509Certificate storedCertificate : keyStoreManager.getCertificates())
        {
            String dn = storedCertificate.getSubjectDN().toString();
            BigInteger serial = storedCertificate.getSerialNumber();

            certificates.add(new Certificate(dn, serial));
        }

        return new JSONWithPadding(certificates, callback);
    }
}
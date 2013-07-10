package es.uji.apps.cryptoapplet.ui.service.rest;

import com.sun.jersey.api.json.JSONWithPadding;
import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.exceptions.SignatureException;
import es.uji.apps.cryptoapplet.crypto.raw.RawSignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESSignatureFormatter;
import es.uji.apps.cryptoapplet.ui.service.model.Base64Data;
import es.uji.apps.cryptoapplet.utils.Base64;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Map;

@Path("sign")
public class SignResource extends AbstractBaseResource
{
    public SignResource() throws GeneralSecurityException, IOException
    {
        super();
    }

    @GET
    @Path("raw")
    @Produces("application/javascript")
    public JSONWithPadding raw(@QueryParam("callback") String callback,
                               @QueryParam("inputUrl") String inputUrl,
                               @QueryParam("dn") String dn)
            throws ConfigurationLoadException, IOException, SignatureException
    {
        Configuration configuration = new ConfigManager().getConfiguration();

        SignatureOptions signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(super.getData(inputUrl));

        Map.Entry<KeyStore.PrivateKeyEntry, Provider> privateKeyEntry = keyStoreManager.getPrivateKeyEntryByDn(dn);
        X509Certificate certificate = (X509Certificate) privateKeyEntry.getKey().getCertificate();
        Provider provider = privateKeyEntry.getValue();
        PrivateKey privateKey = privateKeyEntry.getKey().getPrivateKey();

        Security.removeProvider(provider.getName());
        Security.insertProviderAt(provider, 1);

        SignatureFormatter signatureFormatter = new RawSignatureFormatter(certificate, privateKey, provider);
        byte[] signedData = signatureFormatter.format(signatureOptions);

        return new JSONWithPadding(new Base64Data(signedData), callback);
    }

    @GET
    @Path("xades")
    @Produces("application/javascript")
    public JSONWithPadding xades(@QueryParam("callback") String callback,
                                 @QueryParam("inputUrl") String inputUrl,
                                 @QueryParam("dn") String dn)
            throws ConfigurationLoadException, IOException, SignatureException
    {
        Configuration configuration = new ConfigManager().getConfiguration();

        SignatureOptions signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(super.getData(inputUrl));

        Map.Entry<KeyStore.PrivateKeyEntry, Provider> privateKeyEntry = keyStoreManager.getPrivateKeyEntryByDn(dn);
        X509Certificate certificate = (X509Certificate) privateKeyEntry.getKey().getCertificate();
        Provider provider = privateKeyEntry.getValue();
        PrivateKey privateKey = privateKeyEntry.getKey().getPrivateKey();

        Security.removeProvider(provider.getName());
        Security.insertProviderAt(provider, 1);

        SignatureFormatter signatureFormatter = new XAdESSignatureFormatter(certificate, privateKey, provider);
        byte[] signedData = signatureFormatter.format(signatureOptions);

        return new JSONWithPadding(new Base64Data(signedData), callback);
    }
}

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
import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;
import es.uji.apps.cryptoapplet.ui.service.model.Base64Data;
import es.uji.apps.cryptoapplet.ui.service.model.RemoteContentManager;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Map;

@Path("sign")
public class SignResource
{
    private SignatureOptions signatureOptions;

    @GET
    @Path("raw")
    @Produces("application/javascript")
    public JSONWithPadding raw(@QueryParam("callback") String callback,
                               @QueryParam("inputUrl") String inputUrl,
                               @QueryParam("dn") String dn)
            throws ConfigurationLoadException, IOException, SignatureException, GeneralSecurityException
    {
        initCryptoEnvironment(inputUrl, dn);

        SignatureFormatter signatureFormatter = new RawSignatureFormatter(signatureOptions.getCertificate(),
                signatureOptions.getPrivateKey(), signatureOptions.getProvider());
        byte[] signedData = signatureFormatter.format(signatureOptions);

        return new JSONWithPadding(new Base64Data(signedData), callback);
    }

    @GET
    @Path("xades")
    @Produces("application/javascript")
    public JSONWithPadding xades(@QueryParam("callback") String callback,
                                 @QueryParam("inputUrl") String inputUrl,
                                 @QueryParam("dn") String dn)
            throws ConfigurationLoadException, IOException, SignatureException, GeneralSecurityException
    {
        initCryptoEnvironment(inputUrl, dn);

        SignatureFormatter signatureFormatter = new XAdESSignatureFormatter(signatureOptions.getCertificate(),
                signatureOptions.getPrivateKey(), signatureOptions.getProvider());
        byte[] signedData = signatureFormatter.format(signatureOptions);

        return new JSONWithPadding(new Base64Data(signedData), callback);
    }

    private void initCryptoEnvironment(String inputUrl, String dn) throws ConfigurationLoadException, IOException, GeneralSecurityException
    {
        Configuration configuration = new ConfigManager().getConfiguration();

        KeyStoreManager keyStoreManager = new KeyStoreManager();
        Map.Entry<KeyStore.PrivateKeyEntry, Provider> privateKeyEntry = keyStoreManager.getPrivateKeyEntryByDn(dn);

        RemoteContentManager contentManager = new RemoteContentManager();

        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(contentManager.getData(inputUrl));
        signatureOptions.setCertificate((X509Certificate) privateKeyEntry.getKey().getCertificate());
        signatureOptions.setProvider(privateKeyEntry.getValue());
        signatureOptions.setPrivateKey(privateKeyEntry.getKey().getPrivateKey());
    }
}
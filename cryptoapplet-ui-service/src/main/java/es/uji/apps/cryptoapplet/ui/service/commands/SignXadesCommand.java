package es.uji.apps.cryptoapplet.ui.service.commands;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESSignatureFormatter;
import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;
import es.uji.apps.cryptoapplet.ui.service.DataObject;
import es.uji.apps.cryptoapplet.utils.Base64;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Map;

public class SignXadesCommand implements ServiceCommand
{
    private byte[] dataToSign;
    private Map<String, String> params;

    private KeyStoreManager keyStoreManager;

    public SignXadesCommand(byte[] dataToSign, Map<String, String> params) throws Exception
    {
        this.dataToSign = dataToSign;
        this.params = params;

        keyStoreManager = new KeyStoreManager();
    }

    public DataObject execute() throws Exception
    {
        Configuration configuration = new ConfigManager().getConfiguration();

        SignatureOptions signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new ByteArrayInputStream(dataToSign));

        String dn = params.get("dn");

        Map.Entry<KeyStore.PrivateKeyEntry, Provider> privateKeyEntry = keyStoreManager.getPrivateKeyEntryByDn(dn);
        X509Certificate certificate = (X509Certificate) privateKeyEntry.getKey().getCertificate();
        Provider provider = privateKeyEntry.getValue();
        PrivateKey privateKey = privateKeyEntry.getKey().getPrivateKey();

        Security.removeProvider(provider.getName());
        Security.insertProviderAt(provider, 1);

        SignatureFormatter signatureFormatter = new XAdESSignatureFormatter(certificate, privateKey, provider);
        byte[] signedData = signatureFormatter.format(signatureOptions);

        DataObject data = new DataObject();
        data.put("signature", Base64.encodeBytes(signedData));

        return data;
    }
}
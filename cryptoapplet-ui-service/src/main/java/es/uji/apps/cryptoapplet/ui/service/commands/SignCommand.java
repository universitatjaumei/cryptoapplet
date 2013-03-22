package es.uji.apps.cryptoapplet.ui.service.commands;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.raw.RawFormatter;
import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;
import es.uji.apps.cryptoapplet.ui.service.DataObject;
import es.uji.apps.cryptoapplet.utils.Base64;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Map;

public class SignCommand implements ServiceCommand
{
    private byte[] dataToSign;
    private Map<String, String> params;

    private KeyStoreManager keyStoreManager;

    public SignCommand(byte[] dataToSign, Map<String, String> params) throws Exception
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
        PrivateKey privateKey = privateKeyEntry.getKey().getPrivateKey();

        Formatter formatter = new RawFormatter(certificate, privateKey, privateKeyEntry.getValue());
        SignatureResult signatureResult = formatter.format(signatureOptions);
        byte[] signedData = StreamUtils.inputStreamToByteArray(signatureResult.getSignatureData());

        DataObject data = new DataObject();
        data.put("success", signatureResult.isValid());
        data.put("signature", Base64.encodeBytes(signedData));

        return data;
    }
}
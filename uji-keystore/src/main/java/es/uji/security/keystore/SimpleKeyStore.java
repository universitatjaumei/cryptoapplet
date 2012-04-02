package es.uji.security.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.List;

public interface SimpleKeyStore
{
    void load(InputStream input, String password)
            throws GeneralSecurityException, IOException;

    List<String> aliases() throws KeyStoreException;

    Certificate getCertificate(String alias) throws KeyStoreException;

    List<Certificate> getUserCertificates() throws KeyStoreException;

    Key getKey(String alias) throws GeneralSecurityException;

    Key getKey(String alias, String password) throws GeneralSecurityException;

    Provider getProvider();

    String getAliasFromCertificate(Certificate cer) throws KeyStoreException;
}

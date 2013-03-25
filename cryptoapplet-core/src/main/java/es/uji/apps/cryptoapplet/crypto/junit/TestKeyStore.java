package es.uji.apps.cryptoapplet.crypto.junit;

import java.io.InputStream;

public interface TestKeyStore
{
    String getKeyStoreType();

    InputStream getKeyStore();

    char[] getKeyStorePin();
}

package es.uji.security.keystore.dnie;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;

public class DNIeTest
{
    public static void main(String[] args) throws KeyStoreException, ClassNotFoundException,
            SecurityException, NoSuchMethodException, IllegalArgumentException,
            InstantiationException, IllegalAccessException, InvocationTargetException
    {
        String pkcs11config = "name = DNIE\nlibrary = /usr/lib/opensc-pkcs11.so ";
        InputStream confStream = new ByteArrayInputStream(pkcs11config.getBytes());

        Class sunPkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
        Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);

        Provider pkcs11Provider = (Provider) pkcs11Constr.newInstance(confStream);
        Security.addProvider(pkcs11Provider);
        // KeyStore.getInstance("PKCS11", _pk11provider);
        //
        // // Si pasamos de aqui el dnie esta insertado.
        // Security.removeProvider(_pk11provider.getName());
        // System.out.println("Saliendo true ...");
    }
}

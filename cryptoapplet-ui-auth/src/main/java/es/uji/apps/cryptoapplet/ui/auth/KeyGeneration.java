package es.uji.apps.cryptoapplet.ui.auth;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyGeneration
{
    public static void main(String[] args) throws KeyException, NoSuchAlgorithmException, IOException
    {
        KeyGeneration keyGeneration = new KeyGeneration();
        KeyPair keyPair = keyGeneration.generateKeys();

        FileOutputStream fileOutputStream = new FileOutputStream("public.key");
        fileOutputStream.write(keyPair.getPublic().getEncoded());
        fileOutputStream.close();

        fileOutputStream = new FileOutputStream("private.key");
        fileOutputStream.write(keyPair.getPrivate().getEncoded());
        fileOutputStream.close();
    }

    public KeyPair generateKeys() throws NoSuchAlgorithmException, KeyException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }
}

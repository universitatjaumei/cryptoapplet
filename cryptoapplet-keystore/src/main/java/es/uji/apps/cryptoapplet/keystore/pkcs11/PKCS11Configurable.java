package es.uji.apps.cryptoapplet.keystore.pkcs11;

public interface PKCS11Configurable
{
    String getPKCS11Library();

    byte[] getPKCS11Configuration();
}

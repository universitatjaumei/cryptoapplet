package es.uji.security.keystore.mozilla;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Random;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.crypto.config.OperatingSystemUtils;
import es.uji.security.keystore.IKeyStore;
import es.uji.security.util.RegQuery;

public class MozillaKeyStore implements IKeyStore
{
    private Mozilla _mozilla;
    private String _pkcs11file;
    private String _currentprofile;
    private String _configName;
    private Provider _pk11provider;
    private KeyStore _mozillaKeyStore;
    private RegQuery rq = new RegQuery();
    boolean _initialized;

    public MozillaKeyStore() throws IOException
    {
        _mozilla = new Mozilla();
        _pkcs11file = _mozilla.getPkcs11FilePath();
        _currentprofile = _mozilla.getCurrentProfiledir();

        /*
         * We create that file on a temporary way because we need it to initialize SunPKCS11
         * provider.
         */

        if (OperatingSystemUtils.isWindowsUpperEqualToNT())
        {
            _configName = rq.getCurrentUserPersonalFolderPath() + File.separator + "p11.cfg";
        }
        else
        {
            _configName = "./.p11.cfg.1166440118";
        }

        File f = new File(_configName);

        /*
         * while (f.exists()) { _configName = _configName + System.currentTimeMillis(); f = new
         * File(_configName); }
         */

        FileOutputStream fos = new FileOutputStream(f);

        /*
         * Replaces are for windows, NSS will read the path with / file separator instead of
         * Microsoft standar \ and spaces must be scaped too.
         */

        if (OperatingSystemUtils.isWindowsUpperEqualToNT())
        {
            fos.write(("name = NSS\r" + "library = " + _pkcs11file + "\r"
                    + "attributes= compatibility" + "\r" + "slot=2\r" + "nssArgs=\""
                    + "configdir='" + _currentprofile.replace("\\", "/").replace(" ", "\\ ") + "' "
                    + "certPrefix='' " + "keyPrefix='' " + "secmod=' secmod.db' " + "flags=readOnly\"\r")
                    .getBytes());
        }
        else if (OperatingSystemUtils.isLinux())
        {
            /*
             * TODO:With Linux is pending to test what's up with the white spaces in the path.
             */

            fos.write(("name = NSS-" + new Random().nextInt() + "\n" + "library = " + _pkcs11file
                    + "\n" + "attributes= compatibility" + "\n" + "slot=2\n" + "nssArgs=\""
                    + "configdir='" + _currentprofile + "' " + "certPrefix='' " + "keyPrefix='' "
                    + "secmod=' secmod.db' " + "flags=readOnly\"\n").getBytes());
        }
        fos.close();
    }

    public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException
    {

        ByteArrayInputStream bais = new ByteArrayInputStream(("name = NSS\n" + "library = "
                + _pkcs11file + "\n" + "attributes= compatibility" + "\n" + "slot=2\n"
                + "nssArgs=\"" + "configdir='" + _currentprofile + "' " + "certPrefix='' "
                + "keyPrefix='' " + "secmod=' secmod.db' " + "flags=readOnly\"\n").getBytes());

        _pk11provider = new sun.security.pkcs11.SunPKCS11(bais);
        Security.addProvider(_pk11provider);
        _mozillaKeyStore = KeyStore.getInstance("PKCS11", _pk11provider);

        try
        {
            _mozillaKeyStore.load(null, pin);
            _initialized = true;
        }
        catch (IOException e)
        {
            // We should remove the provider on failure and
            // re-throw the exception to be handled
            Security.removeProvider(_pk11provider.getName());
            throw (e);
        }
    }

    public Enumeration<String> aliases() throws KeyStoreException, Exception
    {
        if (!_initialized)
        {
            throw (new Exception("UninitializedKeyStore"));
        }

        Enumeration<String> e = _mozillaKeyStore.aliases();

        while (e.hasMoreElements())
        {
            System.out.println("Alias: " + e.nextElement());
        }
        return _mozillaKeyStore.aliases();
    }

    public String getAliasFromCertificate(Certificate cer) throws Exception
    {
        if (!_initialized)
        {
            throw (new Exception("UninitializedKeyStore"));
        }

        X509Certificate xcer = (X509Certificate) cer, auxCer = null;
        String auxAlias = null;

        Enumeration<String> e = _mozillaKeyStore.aliases();

        while (e.hasMoreElements())
        {
            auxAlias = (String) e.nextElement();
            auxCer = (X509Certificate) _mozillaKeyStore.getCertificate(auxAlias);
            if ((auxCer.getIssuerDN().equals(xcer.getIssuerDN()))
                    && (auxCer.getSerialNumber().equals(xcer.getSerialNumber())))
            {
                return auxAlias;
            }
        }
        return null;
    }

    public Certificate getCertificate(String alias) throws KeyStoreException, Exception
    {
        if (!_initialized)
        {
            throw (new Exception("UninitializedKeyStore"));
        }

        return _mozillaKeyStore.getCertificate(alias);
    }

    public Certificate[] getUserCertificates() throws KeyStoreException, Exception
    {
        return null;
    }

    public Key getKey(String alias) throws KeyStoreException, Exception
    {
        if (!_initialized)
        {
            throw (new Exception("UninitializedKeyStore"));
        }

        return _mozillaKeyStore.getKey(alias, null);
    }

    public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException,
            Exception
    {
        byte[] res = null;
        PrivateKey privKey = (PrivateKey) _mozillaKeyStore.getKey(alias, null);

        if (privKey == null)
        {
            return null;
        }

        Signature rsa = Signature.getInstance("SHA1withRSA", getProvider());
        rsa.initSign(privKey);
        rsa.update(toSign);
        res = rsa.sign();

        return res;
    }

    public SupportedKeystore getName()
    {
        return SupportedKeystore.MOZILLA;
    }

    public String getTokenName()
    {
        return "Firefox";
    }

    public Provider getProvider()
    {
        return _mozillaKeyStore.getProvider(); // _pk11provider;
    }

    public void setProvider(Provider provider) throws Exception
    {
        // Does nothing, seems non sense by this time.
        throw new Exception("Method not implemented");
    }

    public void cleanUp()
    {
        File f = new File(_configName);
        f.delete();
        Security.removeProvider(_pk11provider.getName());
    }
}
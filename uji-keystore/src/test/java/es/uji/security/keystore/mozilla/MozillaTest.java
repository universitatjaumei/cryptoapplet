package es.uji.security.keystore.mozilla;

import org.junit.Assert;
import org.junit.Test;

import es.uji.security.keystore.pkcs11.devices.Firefox;

public class MozillaTest
{
    @Test
    public void shouldFindExistingLibsoftokn3Installed() throws Exception
    {
        Firefox mozilla = new Firefox();
        Assert.assertNotNull(mozilla.getPKCS11Library());
    }
    
    @Test
    public void shouldFindCurrentProfileDirectory() throws Exception
    {
        Firefox mozilla = new Firefox();
        Assert.assertNotNull(mozilla.getCurrentProfileDirectory());
    }    
}
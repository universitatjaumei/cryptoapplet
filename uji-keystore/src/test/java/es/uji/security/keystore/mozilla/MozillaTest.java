package es.uji.security.keystore.mozilla;

import org.junit.Assert;
import org.junit.Test;

public class MozillaTest
{
    @Test
    public void shouldFindExistingLibsoftokn3Installed() throws Exception
    {
        Mozilla mozilla = new Mozilla();
        Assert.assertNotNull(mozilla.getPKCS11Library());
    }
    
    @Test
    public void shouldFindCurrentProfileDirectory() throws Exception
    {
        Mozilla mozilla = new Mozilla();
        Assert.assertNotNull(mozilla.getCurrentProfileDirectory());
    }    
}
package es.uji.security;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import es.uji.security.crypto.cms.CMSTest;
import es.uji.security.crypto.facturae.FacturaeTest;
import es.uji.security.crypto.jxades.JXAdESTest;
import es.uji.security.crypto.mityc.MITyCTest;
import es.uji.security.crypto.openxades.OpenXAdESTest;

@RunWith(Suite.class)
@Suite.SuiteClasses( { 
    CMSTest.class, 
    FacturaeTest.class, 
    JXAdESTest.class, 
    MITyCTest.class,
    OpenXAdESTest.class
})
public class AllTest
{

}
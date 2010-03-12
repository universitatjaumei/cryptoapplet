package es.uji.security;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import es.uji.security.crypto.cms.CMSTest;
import es.uji.security.crypto.facturae.FacturaeTest;
import es.uji.security.crypto.jxades.JXAdESTest;
import es.uji.security.crypto.mityc.MITyCTest;

@RunWith(Suite.class)
@Suite.SuiteClasses( { 
    CMSTest.class, 
    FacturaeTest.class, 
    JXAdESTest.class, 
    MITyCTest.class 
})
public class AllTest
{

}
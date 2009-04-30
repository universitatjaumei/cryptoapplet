package es.uji.security.keystore.pkcs11;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.Vector;
import java.lang.reflect.Method;


import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.*;

import es.uji.security.keystore.pkcs11.PKCS11HelperException;

public class PKCS11Helper {
	
	private static int MAX_CERTS= 1000;
	
	String _initArgs, _pk11LibPath, _name;
	Vector<X509Certificate> certificates= new Vector<X509Certificate>();

	public PKCS11Helper(String pk11LibPath, String initArgs)
	throws PKCS11HelperException {

		_initArgs= initArgs;
		_pk11LibPath= pk11LibPath;
		 initialize();
	}


	public PKCS11Helper(String pk11LibPath)
	throws PKCS11HelperException {

		_initArgs=null;
		_pk11LibPath= pk11LibPath;
		initialize();

	}


	public String getName(){
		return _name;
	}


	private void initialize() 
	throws PKCS11HelperException {
		
		long hSession= 0;
		long[] slots;
		boolean found= false;
		
		CK_C_INITIALIZE_ARGS cia= new CK_C_INITIALIZE_ARGS();
		CK_ATTRIBUTE[] attrs= new CK_ATTRIBUTE[1];
		CK_ATTRIBUTE attr= new CK_ATTRIBUTE();
		CK_TOKEN_INFO ckti= null;
		

		cia.pReserved= (Object) _initArgs;
		cia.flags= 0;

		PKCS11 p11= null;

		Method[] methods= PKCS11.class.getMethods();
		Method p11Getinstance= null;

		for (int i=0; i<methods.length; i++)
		{
			if (methods[i].getName().equals("getInstance"))
				p11Getinstance= methods[i];
		}

		try{
			
			File _fpk11LibPath= new File(_pk11LibPath);	
			_pk11LibPath= _fpk11LibPath.getCanonicalPath();
		         
  			System.out.println( "_pk11LibPath: " + _pk11LibPath );		
			
			String version= System.getProperty("java.version");
			if ( version.indexOf("1.6")>-1 || version.indexOf("1.7")>-1 ){
				// JRE 1.6 , JRE 1.7
				p11= (PKCS11) p11Getinstance.invoke(null,new Object[] {_pk11LibPath, "C_GetFunctionList", cia, false});
			}
			else if (version.indexOf("1.5")>-1){
				// JRE 1.5
				p11= (PKCS11) p11Getinstance.invoke(null,new Object[] {_pk11LibPath, cia, false});
			}
			else{
				System.err.println("Unsupported version of VM");
				return ;//System.exit(-1);
			}
		} 
		catch(Exception e){
			e.printStackTrace();
			throw new PKCS11HelperException("Problem using java reflection with pkcs11 classes::" + e.getMessage(),
					PKCS11HelperException.errorType.ERR_INVOKE_INITIALIZE);
		}
		

		try{
			slots= p11.C_GetSlotList(true);	
		}
		catch(Exception e){
			throw new PKCS11HelperException("Getting Slot List::" + e.getMessage(),
					PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
		}
   
		for(long k: slots){

			try{	
				ckti= p11.C_GetTokenInfo(k);
				_name= new String(ckti.label);
			}
			catch(Exception e){
				throw new PKCS11HelperException("Getting token Info::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_GET_TOKEN_INFO);
			}

			try {
				hSession= p11.C_OpenSession(k,CKF_SERIAL_SESSION,null,null);
			}
			catch(Exception e){
				throw new PKCS11HelperException("Opening a new Session::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_OPEN_SESSION);
			}
			attr.type= CKA_CLASS;
			attr.pValue= CKO_CERTIFICATE;
			attrs[0]= attr;

			try{	
				p11.C_FindObjectsInit(hSession, attrs);

				long[] l= p11.C_FindObjects(hSession, MAX_CERTS);
			
				p11.C_FindObjectsFinal(hSession);

				for (long i : l){

					CK_ATTRIBUTE attrPriv= new CK_ATTRIBUTE();
					CK_ATTRIBUTE[] attrsP= new CK_ATTRIBUTE[2];

					attrPriv.type= CKA_CLASS;
					attrPriv.pValue= CKA_PRIVATE;

					attr.type= CKA_ID;
					attr.pValue= getID(hSession, i, p11);
					if ( attr.pValue != null ){
						attrsP[0]=attrPriv;
						attrsP[1]= attr;

						p11.C_FindObjectsInit(hSession, attrsP);
						long[] m= p11.C_FindObjects(hSession, MAX_CERTS);
						for (long n : m){
							found= true;
							certificates.add(loadCert(hSession,i,p11));
						}
						p11.C_FindObjectsFinal(hSession);
					}
				}
			}
			catch(Exception e){
				e.printStackTrace();
				throw new PKCS11HelperException("Unsuccesfully FindObjects secuence::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_FIND_OBJECTS);
			}

			try{
				p11.C_CloseSession(hSession);
				if (found) break;
			}
			catch (Throwable e){
				throw new PKCS11HelperException("Cannot close sesion::" + e.getMessage(),
								PKCS11HelperException.errorType.ERR_CLOSE_SESSION);
			}
		}
		try{
			// Should be revised against the code of jdk. 
			// That should be done under normal conditions, but when using com.sun.security classes, 
			// something happen that make future SunPKCS11 provider against mozilla library 
			// fails on session handle.
			
			//p11.C_Finalize(hSession);
			
			p11= null;
			Runtime.getRuntime().gc();
		}
		catch(Throwable e){
			throw new PKCS11HelperException("Cannot Finalize::" + e.getMessage(),
				PKCS11HelperException.errorType.ERR_FINALIZE);
		}
	}



	private X509Certificate loadCert(long session, long oHandle, PKCS11 p11)
	throws PKCS11Exception, CertificateException {

		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[]
		                                        { new CK_ATTRIBUTE(CKA_VALUE) };
		p11.C_GetAttributeValue(session, oHandle, attrs);

		byte[] bytes = attrs[0].getByteArray();
		if (bytes == null) {
			throw new CertificateException
			("unexpectedly retrieved null byte array");
		}
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate)cf.generateCertificate
		(new ByteArrayInputStream(bytes));
	}

	private byte[] getID(long session, long oHandle, PKCS11 p11)
	throws PKCS11Exception, CertificateException {
		
		byte[] bytes= null;
		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[]
		                                        { new CK_ATTRIBUTE(CKA_ID) };
		
		p11.C_GetAttributeValue(session, oHandle, attrs);
		
		if (attrs[0].pValue != null ){
			bytes = attrs[0].getByteArray();
		}	
		
		return bytes;
	}

	
	public X509Certificate[] getCertificates() 
	throws PKCS11HelperException {
		X509Certificate[] xcer= new X509Certificate[0];
		return certificates.toArray(xcer);
	}
}

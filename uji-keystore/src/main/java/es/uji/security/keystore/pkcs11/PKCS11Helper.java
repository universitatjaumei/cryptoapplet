package es.uji.security.keystore.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Vector;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class PKCS11Helper
{

	private static int MAX_CERTS = 1000;
	private static long CKM_RSA_PKCS= 0x00000001;
	private static long CKM_SHA1_RSA_PKCS= 0x00000006;

	String _initArgs, _pk11LibPath, _name;
	Vector<X509Certificate> certificates = new Vector<X509Certificate>();

	public PKCS11Helper(String pk11LibPath, String initArgs) throws PKCS11HelperException
	{
		
		_initArgs = initArgs;
		_pk11LibPath = pk11LibPath;
		initialize();
	}

	public PKCS11Helper(String pk11LibPath) throws PKCS11HelperException
	{
		
		_initArgs = null;
		_pk11LibPath = pk11LibPath;
		initialize();

	}

	public String getName()
	{
		return _name;
	}

	private void initialize() throws PKCS11HelperException
	{

		long hSession = 0;
		long[] slots;
		boolean found = false;

		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];
		CK_ATTRIBUTE attr = new CK_ATTRIBUTE();
		CK_TOKEN_INFO ckti = null;
		
		PKCS11 p11 = getP11Instance();
	
		try
		{
			slots = p11.C_GetSlotList(true); //true is token present, false to get all slots.
		}
		catch (Exception e)
		{
			throw new PKCS11HelperException("Getting Slot List::" + e.getMessage(),
					PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
		}

		for (long k : slots)
		{

			try
			{
				System.out.println("Slot k = " + k );
				for (long x: p11.C_GetMechanismList(k)){
					if ( x == CKM_RSA_PKCS || x == CKM_SHA1_RSA_PKCS ){
						System.out.println("Slot " + k + " has signature capabilities");
						break;
					}
				}

				ckti = p11.C_GetTokenInfo(k);
				_name = new String(ckti.label);
			}
			catch (Exception e)
			{
				throw new PKCS11HelperException("Getting token Info::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_GET_TOKEN_INFO);
			}

			try
			{
				hSession = p11.C_OpenSession(k, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
			}
			catch (Exception e)
			{
				throw new PKCS11HelperException("Opening a new Session::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_OPEN_SESSION);
			}
			
			attr.type = PKCS11Constants.CKA_CLASS;
			attr.pValue = PKCS11Constants.CKO_CERTIFICATE;
			attrs[0] = attr;

			try
			{
				p11.C_FindObjectsInit(hSession, attrs);

				long[] l = p11.C_FindObjects(hSession, MAX_CERTS);

				p11.C_FindObjectsFinal(hSession);

				for (long i : l)
				{

					CK_ATTRIBUTE attrPriv = new CK_ATTRIBUTE();
					CK_ATTRIBUTE[] attrsP = new CK_ATTRIBUTE[2];

					attrPriv.type = PKCS11Constants.CKA_CLASS;
					attrPriv.pValue = PKCS11Constants.CKA_PRIVATE;//CKO_PRIVATE_KEY;

					attr.type = PKCS11Constants.CKA_ID;
					attr.pValue = getID(hSession, i, p11);

					if (attr.pValue != null)
					{
						attrsP[0] = attrPriv;
						attrsP[1] = attr;

						p11.C_FindObjectsInit(hSession, attrsP);
						long[] m = p11.C_FindObjects(hSession, MAX_CERTS);
						if (m.length > 0)
						{
							found = true;
							certificates.add(loadCert(hSession, i, p11));
						}
						p11.C_FindObjectsFinal(hSession);
					}
				}
			}
			catch (Exception e)
			{
				e.printStackTrace();
				throw new PKCS11HelperException("Unsuccesfully FindObjects secuence::"
						+ e.getMessage(), PKCS11HelperException.errorType.ERR_FIND_OBJECTS);
			}

			try
			{
				p11.C_CloseSession(hSession);
				if (found)
					break;
			}
			catch (Throwable e)
			{
				throw new PKCS11HelperException("Cannot close sesion::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_CLOSE_SESSION);
			}
		}
		
		try
		{
			// Should be revised against the code of jdk.
			// That should be done under normal conditions, but when using com.sun.security classes,
			// something happen that make future SunPKCS11 provider against mozilla library
			// fails on session handle.

			// p11.C_Finalize(hSession);

			p11 = null;
			Runtime.getRuntime().gc();
		}
		catch (Throwable e)
		{
			throw new PKCS11HelperException("Cannot Finalize::" + e.getMessage(),
					PKCS11HelperException.errorType.ERR_FINALIZE);
		}
	}

	private X509Certificate loadCert(long session, long oHandle, PKCS11 p11)
	throws PKCS11Exception, CertificateException
	{

		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[] { new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE) };
		p11.C_GetAttributeValue(session, oHandle, attrs);

		byte[] bytes = attrs[0].getByteArray();
		if (bytes == null)
		{
			throw new CertificateException("unexpectedly retrieved null byte array");
		}
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
	}

	private byte[] getID(long session, long oHandle, PKCS11 p11) throws PKCS11Exception,
	CertificateException
	{

		byte[] bytes = null;
		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[] { new CK_ATTRIBUTE(PKCS11Constants.CKA_ID) };

		p11.C_GetAttributeValue(session, oHandle, attrs);

		if (attrs[0].pValue != null)
		{
			bytes = attrs[0].getByteArray();
		}

		return bytes;
	}

	public X509Certificate[] getCertificates() throws PKCS11HelperException
	{
		X509Certificate[] xcer = new X509Certificate[0];
		return certificates.toArray(xcer);
	}
		
	public long[] getSignatureCapableSlots() throws PKCS11HelperException{

		long[] slots;
		
		Vector<Long> vslots = new Vector<Long>(); 

		PKCS11 p11 = getP11Instance();

		try
		{
			slots = p11.C_GetSlotList(true); //true is token present, false to get all slots.
		}
		catch (Exception e)
		{
			throw new PKCS11HelperException("Getting Slot List::" + e.getMessage(),
					PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
		}

		for (long k : slots)
		{
			try {
				for (long x: p11.C_GetMechanismList(k)){
					if ( x == CKM_SHA1_RSA_PKCS ){
						vslots.add(k);
						break;
					}
				}
			} catch (PKCS11Exception e) {
				throw new PKCS11HelperException("Cannot get Mechanism list::" + e.getMessage(),
						PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
			}
		}

		long[] res= new long[vslots.size()];
		for (int i=0; i<vslots.size(); i++){
			res[i]= vslots.get(i);
		}
		
		return res;
	}
	
	public PKCS11 getP11Instance() throws PKCS11HelperException{

		try {
			// OpenJDK 1.7 on Linux Mint has been found to be using NSS as a "java.security" registered provider (looks like the same thing is being done in other distros, see https://bugzilla.redhat.com/show_bug.cgi?id=1167153#c4) and this produces NSS to be initialized as a pure cryptography provider without database files, then the current method tries to initialize NSS again and this initialization is ignored and NSS is still in noDb mode, so no certificate can be retrieved.
			String providerName = "SunPKCS11-NSS";
			SunPKCS11 pkcs11NSSProvider = (SunPKCS11) Security.getProvider(providerName);
			if (pkcs11NSSProvider != null) {
				// removing it as it won't be usable anymore, TODO confirm if it is really not operative anymore
				Security.removeProvider(providerName);
				// TODO look for a cleaner way (API) to do it, without reflection if possible
				Class<? extends SunPKCS11> nssPkcs11Class = pkcs11NSSProvider.getClass();
				Method getTokenMethod = nssPkcs11Class.getDeclaredMethod("getToken");
				getTokenMethod.setAccessible(true);
				Object token = getTokenMethod.invoke(pkcs11NSSProvider);
				Class<?> tokenClass = Class.forName("sun.security.pkcs11.Token");
				Field p11Field = tokenClass.getDeclaredField("p11");
				p11Field.setAccessible(true);
				PKCS11 p11 = (PKCS11) p11Field.get(token);
				p11.C_Finalize(PKCS11Constants.NULL_PTR);
			}
		} catch (Exception e) {
			// not expected, ignore anyway
		}

		Method[] methods = PKCS11.class.getMethods();
		Method p11Getinstance = null;
		PKCS11 p11= null; 

		CK_C_INITIALIZE_ARGS cia = new CK_C_INITIALIZE_ARGS();
		
		cia.pReserved = (Object) _initArgs;
		cia.flags = 0;

		for (int i = 0; i < methods.length; i++)
		{
			if (methods[i].getName().equals("getInstance"))
				p11Getinstance = methods[i];
		}
		
		try
		{
			File _fpk11LibPath = new File(_pk11LibPath);
			_pk11LibPath = _fpk11LibPath.getCanonicalPath();

			String version = System.getProperty("java.version");
			if (version.indexOf("1.5") > -1)
			{
				// JRE 1.5
				p11 = (PKCS11) p11Getinstance.invoke(null,
						new Object[] { _pk11LibPath, cia, false });
			}
			else
			{
				p11 = (PKCS11) p11Getinstance.invoke(null, new Object[] { _pk11LibPath,
						"C_GetFunctionList", cia, false });
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
			throw new PKCS11HelperException("Problem using java reflection with pkcs11 classes::"
					+ e.getMessage(), PKCS11HelperException.errorType.ERR_INVOKE_INITIALIZE);
		}
		
		return p11; 
	}


	public static void main(String[] args) throws PKCS11HelperException{
		PKCS11Helper pk11h= new PKCS11Helper("/usr/lib/libclauerpkcs11.so", "");

		for (X509Certificate xc: pk11h.getCertificates()){
			System.out.println(xc.getSubjectDN());    		
		}

		//Lets try to get slots by a given mechanism: 
		for (long i: pk11h.getSignatureCapableSlots()){
			System.out.println("Slot " + i + " is signature capable.");
		} 
	}
}

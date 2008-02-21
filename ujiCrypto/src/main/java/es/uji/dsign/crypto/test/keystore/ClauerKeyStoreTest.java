package es.uji.dsign.crypto.test.keystore;

import es.uji.dsign.crypto.keystore.ClauerKeyStore;

public class ClauerKeyStoreTest
{
	public static void main(String[] args)
	{
		try
		{
			new ClauerKeyStore();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}
}

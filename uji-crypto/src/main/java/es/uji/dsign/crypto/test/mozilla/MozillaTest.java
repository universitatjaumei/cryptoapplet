package es.uji.dsign.crypto.test.mozilla;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.util.encoders.HexEncoder;

import es.uji.dsign.crypto.mozilla.Mozilla;
import es.uji.security.util.Base64;
import es.uji.security.util.RegQuery;


public class MozillaTest
{
	public static void main(String[] args)
	{
		Mozilla m = new Mozilla();
		RegQuery r = new RegQuery();

		System.out.println("Current profile dir:           " + m.getCurrentProfiledir());
		System.out.println("CurrentUserPersonalFolderPath: " + r.getCurrentUserPersonalFolderPath());
		System.out.println("AbsoluteApplicationPath:       " + m.getAbsoluteApplicationPath());

		HexEncoder h = new HexEncoder();
		
		try
		{
			ByteArrayOutputStream ot = new ByteArrayOutputStream();
			System.out.println("Decoding: ");
			h.decode("731bd7d6d530298467c7648d8939128e33a2b39d", ot);
			System.out.println("res= " + new String(Base64.encode(ot.toByteArray())));
		}
		catch (Exception e)
		{
			System.out.println("how");
			e.printStackTrace();
		}
	}

}

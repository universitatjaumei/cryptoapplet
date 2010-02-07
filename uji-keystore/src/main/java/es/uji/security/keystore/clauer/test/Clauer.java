package es.uji.security.keystore.clauer.test;

import java.io.ByteArrayInputStream;
import java.io.File;

import es.uji.security.crypto.config.OS;

public class Clauer
{

    public Clauer()
    {

    }

    public String getPkcs11FilePath()
    {

        if (OS.isWindowsUpperEqualToNT())
        {
            String filePath = "C:\\WINDOWS\\system32\\pkcs11-win.dll";
            File f = new File(filePath);
            if (f.exists())
                return filePath;

            filePath = "C:\\WINNT\\system32\\pkcs11-win.dll";
            f = new File(filePath);
            if (f.exists())
                return filePath;

            return null;
        }
        else if (OS.isLinux())
        {
            String filePath = "/usr/local/lib/libpkcs11.so";
            String filePath2 = "/usr/local/lib/libclauerpkcs11.so";

            File f = new File(filePath);
            File f2 = new File(filePath2);

            if (f.exists())
                return filePath;

            else if (f2.exists())
                return filePath2;
        }

        return null;
    }

    public ByteArrayInputStream getPkcs11ConfigInputStream()
    {

        String _pkcs11file = getPkcs11FilePath();

        ByteArrayInputStream bais = null;

        bais = new ByteArrayInputStream(("name = Clauer\r" + "library = " + _pkcs11file + "\r"
                + "attributes= compatibility" + "\r" + "slot=1\r").getBytes());
        return bais;
    }

    public String getPkcs11InitArgsString()
    {
        return null;
    }
}

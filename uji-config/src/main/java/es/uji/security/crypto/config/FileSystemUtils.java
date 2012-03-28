package es.uji.security.crypto.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FileSystemUtils
{
    public static void dumpToFile(String fileName, byte[] data) throws IOException
    {
        if (fileName != null && fileName.length() > 0)
        {
            FileOutputStream fos = new FileOutputStream(fileName);
            fos.write(data);
            fos.flush();
            fos.close();
        }
    }

    public static void dumpToFile(File file, InputStream in) throws IOException
    {
        System.out.println("Dumping to file available: " + in.available());

        if (file != null /* && file.length() > 0 */)
        {
            byte[] buffer = new byte[2048];
            int length = 0;

            FileOutputStream fos = new FileOutputStream(file);

            while ((length = in.read(buffer)) >= 0)
            {
                fos.write(buffer, 0, length);
            }

            fos.close();
        }
    }

    public static void copyfile(String srFile, String dtFile) throws FileNotFoundException,
            IOException
    {
        File f1 = new File(srFile);
        File f2 = new File(dtFile);

        if (!f2.exists())
        {
            InputStream in = new FileInputStream(f1);
            OutputStream out = new FileOutputStream(f2);

            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) > 0)
            {
                out.write(buf, 0, len);
            }
            in.close();
            out.close();
        }
    }
}
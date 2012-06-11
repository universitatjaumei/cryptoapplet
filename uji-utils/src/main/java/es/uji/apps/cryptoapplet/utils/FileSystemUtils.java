package es.uji.apps.cryptoapplet.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

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

    public static void dumpToFile(File file, InputStream input) throws IOException
    {
        dumpToFile(file.getAbsolutePath(), StreamUtils.inputStreamToByteArray(input));
    }

    public static void copyfile(String source, String destination) throws FileNotFoundException,
            IOException
    {
        File sourceFile = new File(source);
        File destinationFile = new File(destination);

        if (!destinationFile.exists())
        {
            dumpToFile(destinationFile, new FileInputStream(sourceFile));
        }
    }
}
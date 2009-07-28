package es.uji.security.crypto.xmldsign.odf;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import es.uji.security.util.OS;

public class ODFDocument
{
    private Map<String, byte[]> jarContents = null;
    
    public ODFDocument(InputStream inputStream) throws IOException
    {
        JarInputStream jarInputStream = new JarInputStream(inputStream);
        
        jarContents = new HashMap<String, byte[]>();
        
        JarEntry entry = null;
    
        while ((entry = jarInputStream.getNextJarEntry()) != null)
        {
            if (!entry.isDirectory())
            {
                String entryName = entry.getName();
                byte[] data = OS.inputStreamToByteArray(jarInputStream);
                
                jarContents.put(entryName, data);
            }
        }        
    }
    
    public byte[] getEntry(String entryName) throws IOException
    {        
        return jarContents.get(entryName);
    }

    public boolean hasEntry(String entryName) throws IOException
    {        
        return jarContents.containsKey(entryName);
    }
    
    public ArrayList<String> getFileList() throws IOException
    {        
        return new ArrayList<String>(jarContents.keySet());
    }
}

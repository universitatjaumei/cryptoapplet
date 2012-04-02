package es.uji.security.keystore.pkcs11;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.List;

public class PKCS11Device
{
    protected List<String> guessProfileDirectories;

    protected String getFirstExistingFileName(List<String> guessPaths, String fileName)
    {
        for (String path : guessPaths)
        {
            if (fileNameExistsInPath(path, fileName))
            {
                return path + fileName;
            }
        }

        return null;
    }

    private boolean fileNameExistsInPath(String path, final String fileName)
    {
        File basePath = new File(path);
        String[] fileList = basePath.list(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.equals(fileName);
            }
        });

        return (fileList != null && fileList.length > 0);
    }

    protected List<String> getLibraryPaths(String basePath, final String expression, String subPath)
    {
        String[] firefoxPaths = new File(basePath).list(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                if (expression.startsWith("*"))
                {
                    return name.endsWith(expression.substring(1));
                }
                else if (expression.endsWith("*"))
                {
                    return name.startsWith(expression.substring(0, expression.length() - 2));
                }
                else
                {
                    return name.equals(expression);
                }
            }
        });

        List<String> paths = new ArrayList<String>();

        for (String path : firefoxPaths)
        {
            paths.add("/usr/lib/" + path + subPath);
        }

        return paths;
    }
}

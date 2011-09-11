package es.uji.security.keystore.clauer;

public class ClauerTest
{
    public static void main(String[] args)
    {
        Clauer cl = new Clauer();
        ClauerRunTime clr = new ClauerRunTime();

        if (clr.isRunTimeRunning())
        {
            try
            {
                String[] devs = clr.enumerateDevices();

                if (devs.length > 0)
                {
                    cl.open(devs[0]);

                    String[] aliases = cl.getCertificateAliases();

                    for (int i = 0; i < aliases.length; i++)
                    {
                        System.out.println("Got Certificate alias: " + aliases[i]);
                    }
                    System.out.println(cl
                            .getCertificate("a165612e9aaa1c2dd4ece0acd1b526d35420c997"));
                    cl.close();

                    /* Now open an auth Session */
                    if (cl.openAuth(devs[0], "123clauer"))
                    {
                        System.out.println("\nOpen Auth OK");
                        System.out.println("Llave: "
                                + cl.getPrivateKey("a165612e9aaa1c2dd4ece0acd1b526d35420c997"));
                    }
                    else
                    {
                        System.err.println("Incorrect password ");
                    }
                }
                else
                {
                    System.err.println("No se detectaron clauers!");
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        else
        {
            System.err.println("El RunTime no esta en marcha o no esta instalado");
        }
    }
}

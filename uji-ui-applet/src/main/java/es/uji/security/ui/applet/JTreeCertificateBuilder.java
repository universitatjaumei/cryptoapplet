package es.uji.security.ui.applet;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.swing.tree.DefaultMutableTreeNode;

import org.apache.log4j.Logger;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.keystore.SimpleKeyStore;
import es.uji.security.keystore.X509CertificateHandler;
import es.uji.security.util.i18n.LabelManager;

public class JTreeCertificateBuilder
{
    private Logger log = Logger.getLogger(JTreeCertificateBuilder.class);

    public JTreeCertificateBuilder()
    {
    }

    public DefaultMutableTreeNode build(Hashtable<SupportedKeystore, SimpleKeyStore> ksh)
    {
        log.debug("Building certificate tree");

        DefaultMutableTreeNode root = new DefaultMutableTreeNode(
                LabelManager.get("LABEL_TREE_ROOT"));

        if (ksh == null)
        {
            throw new IllegalArgumentException("Keystore hastable can't be null");
        }

        X509Certificate xcert;
        X509CertificateHandler certHandle;
        boolean found = false;

        Vector<String> caStrs = new Vector<String>();
        Vector<DefaultMutableTreeNode> caNodes = new Vector<DefaultMutableTreeNode>();

        for (SimpleKeyStore keystore : ksh.values())
        {
            try
            {
                List<Certificate> certs = keystore.getUserCertificates();

                if (certs != null)
                {

                    for (Certificate cer : certs)
                    {
                        found = false;
                        xcert = (X509Certificate) cer;

                        if (xcert != null)
                        {
                            certHandle = new X509CertificateHandler(xcert);

                            for (int j = 0; j < caStrs.size(); j++)
                            {
                                if (((String) caStrs.get(j)).equals(certHandle
                                        .getIssuerOrganization()))
                                {
                                    ((DefaultMutableTreeNode) caNodes.get(j))
                                            .add(new DefaultMutableTreeNode(certHandle));
                                    found = true;

                                    log.debug("Added new certificate " + certHandle);
                                }
                            }

                            if (!found)
                            {
                                String issuerOrg = certHandle.getIssuerOrganization();
                                DefaultMutableTreeNode nodeAux = new DefaultMutableTreeNode(
                                        issuerOrg);

                                log.debug("Added new CA " + issuerOrg);

                                nodeAux.add(new DefaultMutableTreeNode(certHandle));

                                log.debug("Added new certificate " + certHandle);

                                caStrs.add(issuerOrg);
                                root.add(nodeAux);
                                caNodes.add(nodeAux);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        return root;
    }
}

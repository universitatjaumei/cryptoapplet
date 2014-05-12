package es.uji.security.ui.applet;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.tree.DefaultMutableTreeNode;

import org.apache.log4j.Logger;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.keystore.IKeyStore;
import es.uji.security.keystore.X509CertificateHandler;
import es.uji.security.util.i18n.LabelManager;

public class JTreeCertificateBuilder
{
    private Logger log = Logger.getLogger(JTreeCertificateBuilder.class);
    
    public JTreeCertificateBuilder()
    {
    }

    public DefaultMutableTreeNode build(Hashtable<SupportedKeystore, IKeyStore> ksh) throws Exception
    {
        log.debug("Building certificate tree");
        
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(LabelManager.get("LABEL_TREE_ROOT"));

        if (ksh == null)
        {
            throw new IllegalArgumentException("Keystore hastable can't be null");
        }

        X509Certificate xcert;
        X509CertificateHandler certHandle;
        boolean found = false;

        Vector<String> caStrs = new Vector<String>();
        Vector<DefaultMutableTreeNode> caNodes = new Vector<DefaultMutableTreeNode>();

        for (SupportedKeystore supportedKeystore : ksh.keySet())
        {
            try
            {                               
            	IKeyStore keystore = ksh.get(supportedKeystore);
                Certificate[] certs = keystore.getUserCertificates();
                
                if (certs != null)
                {

                    for (Certificate cer : certs)
                    {
                        found = false;
                        xcert = (X509Certificate) cer;                        
                        
                        if (xcert != null)
                        {
                            certHandle = new X509CertificateHandler(xcert, "none", keystore);
                            for (int j = 0; j < caStrs.size(); j++)
                            {
                                if (((String) caStrs.get(j)).equals(certHandle
                                        .getIssuerOrganization()))
                                {
                                	found = true;
                                	
                                	DefaultMutableTreeNode caNode = (DefaultMutableTreeNode) caNodes.get(j);
                                	DefaultMutableTreeNode certHandleNode = new DefaultMutableTreeNode(certHandle);
                                    int childIndex = certIndex(caNode, certHandleNode);
                                    if (childIndex >= 0)
                                    {
                                    	if (supportedKeystore.equals(SupportedKeystore.PKCS11))
                                    	{
                                    		((DefaultMutableTreeNode) caNode.getChildAt(childIndex)).setUserObject(certHandleNode.getUserObject());
                                    	
                                    		log.debug("Replaced with PKCS11 certificate " + certHandle);
                                    	}
                                    }
                                    else
                                    {
	                                    ((DefaultMutableTreeNode) caNodes.get(j))
	                                            .add(new DefaultMutableTreeNode(certHandle));
	                                    
	                                    log.debug("Added new certificate " + certHandle);
                                    }
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

	private int certIndex(DefaultMutableTreeNode caNode, DefaultMutableTreeNode certHandleNode) {
		Enumeration children = caNode.children();
		int i = 0;
		
		
		while (children.hasMoreElements())
		{
			DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) children.nextElement();
			X509CertificateHandler treeNodeHandle = (X509CertificateHandler) treeNode.getUserObject();
			X509CertificateHandler certHandle = (X509CertificateHandler) certHandleNode.getUserObject();
			if (treeNodeHandle.getCertificate().getSubjectDN().equals(certHandle.getCertificate().getSubjectDN()))
			{
				return i;
			}
			i++;
		}
		
		return -1;
	}
}

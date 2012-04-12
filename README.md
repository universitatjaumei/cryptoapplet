# CryptoApplet #

CryptoApplet is a Java applet for advanced digital signature creation developed by the [Universitat Jaume I](http://www.uji.es). The procedure is very simple: given a data input and a configuration determined by the server, the web client will create a digital signature of the data, and a representation of the signature is obtained in the format specified in the configuration.

![Screenshot](https://github.com/borillo/cryptoapplet/raw/master/cryptoapplet.png)

The signature representation formats supported by CryptoApplet are the following:

* Raw signature.
* CMS/PKCS#7.
* XML: from XML Signature to XAdES-X-L.
* PDF: PAdES signature with timestamp.
* ODT: XML Signature.

Certificate management is done transparently for the user through direct access to CryptoAPI, if we are using Microsoft Internet Explorer, or to PKCS#11 if we are using Firefox (either in Windows or GNU/Linux). Stored certificates can also be used if the client system has the Clauer software installed.

The applet can also be executed in the operating systems Microsoft Windows XP and GNU/Linux, the only requirement being having Sun's Java Virtual Machine (version 1.5 o higher) installed.

More information in the public list at [Google Groups](https://groups.google.com/a/uji.es/group/cryptoapplet?lnk=)

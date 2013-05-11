package es.uji.apps.cryptoapplet.crypto.junit;

import es.uji.apps.cryptoapplet.utils.Base64;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class KeyStoreAnfActivo implements TestKeyStore
{
    private String keyStoreData = "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCAz4wgDCABgkqhkiG9w0BBwGggCSABIIDJjCCAyIwggMe\n" +
            "BgsqhkiG9w0BDAoBAqCCArEwggKtMCcGCiqGSIb3DQEMAQMwGQQUpRWJxSXSctC3HmVIR5EjLteS\n" +
            "gtICAWQEggKAH173NfjSat+f5O7bP672xUM75cGnI0Gb5jWz6JP5oXsLf0PyxDUNrsrZ75H4iHmj\n" +
            "rtfaaKoOj4Q6KXLPdMM9RlADPgksx4mqc9kk1jRnQUOCUGpFI0RWEv1zqxRpCr3JIHyyBwTq+1ND\n" +
            "G7N5yT/8R3UNX6nYwZpqtPi4pMcOe4zTfXNnI/g4JK4Ui1JRLpl3e7d6tpYdH/l6Z4L+bdG74wPX\n" +
            "8tqWE84wYYowpH5yaTtcqSyXCKU0+iK/D4atrmEklznPd/MP0DunT0YtoQYDuuT4hKM5bj34MeIV\n" +
            "MXWQDr60ugvs1q8b5xtG/84udBH7QVjw/EYP7c0kEb3kPRUf49r/C71YgoGWBzSc/eJgzfg8XEvc\n" +
            "5hFITbecQehq+Ho8g7Eh+XS3WsVjK0oA2CxXiwKD8gzDhaC4t3Kr5kCgwuhs5hlpbo0GF4uWK/j5\n" +
            "LoeAgJWJqOD2MkTgiZo36Mu62VJ4fim0NU3wVZmTdFwTME+n4qEANvANrdBuZIkRaTFDsABFfXUU\n" +
            "uM8Hc3p+TB3h/X1/DTFoO+Pdekfc3184/KfqhgIgsQhckzjA0lzbD44SzXwIePMOxCXcld4hHqwW\n" +
            "DUCaRzvM7n1Jg29QPFJ6EcVkJnRRVfriV0mZLy3rd64rYYsAVhmgExvWhYwXY0+aF/K/fA6j8WWM\n" +
            "4kInolYhUFPUeQ96T7J13dFzOdMpyQprsLUXtg7/PKFwZsxmJkvXpCC2l+qHYEOQRailhl7XxKfW\n" +
            "DMj6vPD5dZXLXAfdHouB9LwLT6kHJzdLk9pFMxRYKHz+2Mttw0IM4dsqfnSfYxqNDOBRPZ+4pLHe\n" +
            "Kt0Kme9gUya9CGJiq8HRMIFsxu+jTjFaMCMGCSqGSIb3DQEJFTEWBBSxTxAznF2uoOtMW+fJUoDN\n" +
            "6B+rJDAzBgkqhkiG9w0BCRQxJh4kAEEATgBGACAAVQBzAHUAYQByAGkAbwAgAEEAYwB0AGkAdgBv\n" +
            "AAQBAAQBAAQBAAQBAASCDIIAMIAGCSqGSIb3DQEHBqCAMIACAQAwgAYJKoZIhvcNAQcBMCcGCiqG\n" +
            "SIb3DQEMAQYwGQQUjiun539O59z/MBdiAAdAEWZRxL8CAWSggASCDDBaUYXHmvK0TSCVgVeR9VrQ\n" +
            "sKpzBnSLV+GNCHgE/JkwI/qcOUjpYkEwhLU2XoBQDArFY8qdI3FYWl1O+pEfKWiAPddek8Y2cJSG\n" +
            "MaCrZ3Hobrg467V9G6v7oClpGFGQ2h1QtexFr5inutMS90xJFEXkYx8LVpPjBHJcBxvrQKV1ovak\n" +
            "wG00oQcKHp+mXza+lLjRzMDu+tIk07Dfs04Ssc4N16MbyHwNrTi+wA/uCR1ToC9NrEgzndpZ5LEo\n" +
            "DuHnWN9Tg3JUFAUC28CYjliyRkUckWdkNHaMM5dUuclw6IlXFfvPhDnIGRdX5NiaQHl3vZw5NrqX\n" +
            "AzC8utwgtT4IUR+jQS2MK/BDFeMRLWDZAwfcGqgna3XBJ97YEbRVR0VG4IhBFXaXLXinH5kQy0AI\n" +
            "dOJQ3soBLQTuomdIKXSLilPRWMtdmPY7hP6ci37HtNHlAaI1sWRJZZ4tIHld/L1t7F/eDMxcvX7b\n" +
            "Eh/Bi5bVTPWqYj/k0xobArYoHfDYz/IT58zHQKoRGzZ3V4DajfGfmXXsoeXV+IZeLXv4tPJYLE9E\n" +
            "d3gESPRRpUN0AGQkqZ1DLosuCtQNy20jwWFbttSuvPed9b7dD+v/XW2kedI0FIu1YeSVAzC84jsj\n" +
            "9VBBEp5bWHZ6jvLRmKzknnWRnQtJ/wuNP+Uh3DHObOI+NMlt99DJIhi9TLPGeyRIzg7XbUWjFYU6\n" +
            "fKRFVlEAm2HPmv9qxv2fejjlRgGB0Y69YbgasUoM4vo6LsyUvoEdLcxjGIElUPzUVuQ4fpqPvqq4\n" +
            "+pogOwMOBFzzLKkDtl92BvwOOj3SHuagTZqSgl7NB2TNPIyncmbRrxnKm1iH+Sir9SDY3/NAp1Pp\n" +
            "39Vu5inCAdD38DCbfKnMdC/LrTAmKc+41BVd4KtzSaiOd0e2WuxVXC7/TTUmK4ehkClesHMhvIhk\n" +
            "l17/nIcPZYAdYFRuFEkOBPgse4DtFd77RvH2dxPYdUlG2zbxNbJoo59ao1S8a55tO54jAqoypGvT\n" +
            "i9L9qFiw/YTBVzzWxjM+Kdfn2EaNL52rS0/EDbqUs57uTNK1aAu9ppQa6vRQFhjW38fmFsxMmsz1\n" +
            "BeNPUXta+1gNa88LHHdENQ4RiQQPn5U2pHlNzjA038yDPjeAj264SOqR7vc25jp9e16vDIWM0srK\n" +
            "pGC2WI9om1bINcVQSF/3UmGv0dCwAiAbsFAoqGHz5EdTuXhBo5rIRgT++lvbJ58sDkDW14aSB+M6\n" +
            "JDfBOYHcXrZn1oU3aWNnrKodVmojoAPP2nSnqRRU3eFtH9f/F1cwSy5Qf5CNVhuQxL8sGxuUxO16\n" +
            "22Rr9qOwWYHBRn1kUz4XqxFnJdoNPxUyzIWx6k4fxMjP8fHOJsb3gTji0r80wGk4tGyZyF0J4HQe\n" +
            "Xf7+nxR38jiq5EEUjVvHNlLQY4oNvQfblM343qRbxA1k297CKntu/+oWB01a4fVqLVIUPHGP/qOU\n" +
            "Ra7DasCwND7NvKvG5uH2DQLMvx/MdedqStyJe+a31we9zxwZ7hkFwLtXqzi+nzs4F8leVoILGr6W\n" +
            "ygsmnlaDMjgVdlP/qm6/p/c2uya+5Rk4yHyEbPtxIg1e4trkmbjbG0AMsT5T2+trcnfGj8pM9p2u\n" +
            "//fWPZgN08HgDtsQB8LuCxuZ5AWYM85Nnhtj6AYp6K09tf79HLoYEhQFVrzI0Mt2SPQladVzvyvc\n" +
            "NyeetDeKBKGsHL54tW1Y+hWRn72hmqnKzPoF3Mj7Xp1zYfWYbSOdlnO6FV/Khz3YM9XaKIBr4XWB\n" +
            "X8OWjL5hQa04LrPxeHO9Cl6jhM6EJ6gSF5QFEGN30lCXoz28McNiBsbxgvdq5sXQZWxuu7vdDfHv\n" +
            "A4T63su1ckS1GjeT1IXGEvPuVneo76xeBBoWepOZcaU+6RWX7LhDvKL7JglcubcHcdFFQIcuZIeL\n" +
            "wUN0vkVaDHoOx9mdVQKHJjcL1HPRXscTgDpJD080AGTJypxoA1QHX0DGQwAMJSMHWDX5Rds6Lsmh\n" +
            "j+vVLzSG7DKe61KN0FOz6w031IZfL+jDSP+SZFk58cG1xPO/vuYvLD0kBy6VB66UiAkqhPbKJAH0\n" +
            "9ZDXORqesNt+w0lGNfB8jEwhhftsZAGH+nIyNe7Qr2e/+ZT70oX75wJ/IEafQiZG793d+b2B/PD6\n" +
            "JBiY2H9mzR7lfowuVSvwqIOrpGfj7WuyX85U99OOLS0pHAkCGyPTf7ibCJGCXhCDSLp8deOE9vdo\n" +
            "gQGONvo14ct872seqaU2baQ0Z2QqDiAO4M4/Gt2AcGvjcQN05nl8Gvunw7I5NFTKeXg8PE4CuCKd\n" +
            "D5OhvRaL6MnPIfomZ1CkchfE3zrDiczl8+tmiqd1INcDahx/Xs+net2qEe2m8Kq6xZszG3od0SsC\n" +
            "Acytft4jzYDmySL4ZnP9r17/A1SmNXOx0CHMf2RgZ/oGvf5MPXQgL6eNevV5uZJssekLK0w6Z+O3\n" +
            "VCMnPK14rN0u4nYhKg8l0wkoBUJnvMY5gzTARt/222tRwOVSKe2D5XHzUZfcxj2nzwt2WrcHVKYV\n" +
            "tg1w/5N5QdLdcdwWRzdEFm4FrnqdZSMd5RX88TZqtIDNnnqBmMGQqUdSk7LoSAtbRlYANMZ9RDeg\n" +
            "obnEeiH82XNUMFkYknuWDVKrYMsFWh5IknVMmdImKVFmMg1RH2O+uNCIYNPhcZTBxx01b9mk0tfF\n" +
            "oxN2x/laGD3Eh6/fTV4edAETz1EXLjtLMiHq2l1xQY8Qs0P2b2OfjTlWEzIxzpWNL38eapEhpwyk\n" +
            "B+lE3GioOJx77bGbe5403iVzVX9jynxzY1S3H/scXhgCvRZx2AhU1VyYgk4em+rDYyX64MAjL205\n" +
            "9HLua+YvfvL+Qkx/17Uu2bGE4v0IMDpsX4pjRJB/+n7ZKBxcUWKQL7b3y+zrWxgPu6SiHDj8we+X\n" +
            "qHxGIH/QP1hzX44CVDJ3+JFwTsunhX/nbDZ4jyyWxEZX3frMIYG1rqcb3Xy7SbvxsBmfNC3Ow05v\n" +
            "mgQRQ1abBqFPKY2OeJEHkeAqLFUqOlulElA7Ugw7djVjZAdE1xGzY5D/DBOggvM04LvdvG1x5aPe\n" +
            "ZNscum93TOOoipMYYI3QyacedxUjMKWVd67yyUIOagbDT+NyTXKjbP9KUgw6eGz40Np4RKXGEam8\n" +
            "oX9zYHXkM6SVNVcCTt1gzpAfh9OQYR1t3pRSZqUYKNKqKXMEjmKbMp6U6qHEz9XkfnuisClCQgIa\n" +
            "CHJwCL2ZY7qc2mxdPaeGJf3ljH93dJOGbQp4k67RYJe3ZMASNTBsJ/PnHTIh0ppHDWzub5W7SqdL\n" +
            "98tKXbUUdjGZpaFAX8Rk9CNCurenrvlGJxIHlFOLlSSga76gie8ZpUAUt7LIXL58XXKpmMvd4Qo+\n" +
            "MJa0ADwn86F3f8LOOER94SstrQFB/Fq4iTCS04U7V9US6Qd8Csd5GEI2R+xlOrvwrCZIRyghYNva\n" +
            "iqa90dnD3d4pkafMngZ6GNCSgxb0fbggvziKkqvN3zwxyof3b9FgZ4yd/yhqmoxY7vL9duBzvYVe\n" +
            "n/J2MwhcwKvhTkwD2+THxEs7w2ktruhbuexE1E4XdhZHVLP9eVqVhl/q7boO8Xf5PgnET3tAABTm\n" +
            "hmws613iadzpsxJyhxWVL2PUOtQcU6PXCLN8TlTYNHkJvZz8Hww5NBELTv/KDdoS/tRJ8yCVfNX1\n" +
            "RG6qF4vgJA8UGI9X2QjoxxoZXc4ai+w+7l9mxuQZsNPgxb1+Dox3pe+yAm2vIwS6XcnHpbTuIXYH\n" +
            "3t/9qLnD+XSqxEyn0NzuE1wbcHMpN+c9fGMqSJm5eqSufD5o2rTWPYqXojg9Q4jbyZR3rdjPrPoh\n" +
            "p3FXVZcTDSO7A84dIeoHqhn1ktFQ6jbPwcg6AGXFiwsdUQsXQhv/DbCxtd2zzB3uH4TkVHsR40i9\n" +
            "U5l1ZQCIMxcEn02rKfPZUSALZFI4hJyToiK1X/BuJzgYs+zGe8ExUjvMRgkpKMi5x+pfFCdSby1a\n" +
            "WTL1QQjnp/fEoBQxMCcBE6IbUZDkYBuLt4hqBW4QLl+J9AXC+kxXv+1UcIkR55zjsDq7oHreei5Z\n" +
            "7/UzO7ZvqCidpuyzlhIPoA/ZWFzLwx+42VGH18F+YkZ1xaw7N1YvDX9OHYRzYDvBodnOha1vpEaj\n" +
            "aKbQ0HeaWuNGMkpMn9X1VI8TRv6qdYiv1UAABAEABAEABAEABAEABAEABAEABAEABAEABAEABAEA\n" +
            "BAEAAAAAAAAAMDwwITAJBgUrDgMCGgUABBREYImUbJEClYjvILAmEgiwTKezwAQUlbsn/2bN51H/\n" +
            "kfti/auB7FAAVd4CAWQAAA==\n";

    @Override
    public String getKeyStoreType()
    {
        return "PKCS12";
    }

    @Override
    public InputStream getKeyStore()
    {
        return new ByteArrayInputStream(Base64.decode(keyStoreData));
    }

    @Override
    public char[] getKeyStorePin()
    {
        return "12341234".toCharArray();
    }
}
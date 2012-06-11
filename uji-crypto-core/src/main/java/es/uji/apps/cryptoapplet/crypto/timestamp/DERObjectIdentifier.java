package es.uji.apps.cryptoapplet.crypto.timestamp;

import java.math.BigInteger;

public class DERObjectIdentifier        
{                               
                                                                     

   public static String getOIDasString(
        byte[]  bytes, int ini, int fin)  
    {                   
        StringBuffer    objId = new StringBuffer();
        long            value = 0;                 
        BigInteger      bigValue = null;           
        boolean         first = true;              

        for (int i = ini; i != ini+fin; i++)
        {                                      
            int b = bytes[i] & 0xff;           

            if (value < 0x80000000000000L) 
            {                              
                value = value * 128 + (b & 0x7f);
                if ((b & 0x80) == 0)             // end of number reached
                {                                                        
                    if (first)                                           
                    {                                                    
                        switch ((int)value / 40)                         
                        {                                                
                        case 0:                                          
                            objId.append('0');                           
                            break;                                       
                        case 1:                                          
                            objId.append('1');                           
                            value -= 40;                                 
                            break;                                       
                        default:                                         
                            objId.append('2');                           
                            value -= 80;                                 
                        }                                                
                        first = false;                                   
                    }                                                    

                    objId.append('.');
                    objId.append(value);
                    value = 0;          
                }                       
            }                           
            else                        
            {                           
                if (bigValue == null)   
                {                       
                    bigValue = BigInteger.valueOf(value);
                }                                        
                bigValue = bigValue.shiftLeft(7);        
                bigValue = bigValue.or(BigInteger.valueOf(b & 0x7f));
                if ((b & 0x80) == 0)                                 
                {                                                    
                    objId.append('.');                               
                    objId.append(bigValue);                          
                    bigValue = null;                                 
                    value = 0;                                       
                }                                                    
            }                                                        
        }                                                            

        return objId.toString();
    } 
   
   public static String getHashAlgorithFromOID(String oid){
	   
	   if (oid.equals("1.3.14.3.2.26")){
		   return "SHA1"; 
	   }
	   else if (oid.equals("2.16.840.1.101.3.4.2.1")){
		   return "SHA256";
	   }
	   else if (oid.equals("2.16.840.1.101.3.4.2.2")){
		   return "SHA384"; 
	   }
	   else if (oid.equals("2.16.840.1.101.3.4.2.3")){
		   return "SHA512";
	   }
	   
	   return "UNKNOWN";
   }  
    
}
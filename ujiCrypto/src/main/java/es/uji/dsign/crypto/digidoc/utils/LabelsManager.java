/*
 * LabelsManager.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package es.uji.dsign.crypto.digidoc.utils;

import java.util.Locale;
import java.util.ResourceBundle;
import java.util.PropertyResourceBundle;
import java.io.InputStream;
import java.util.MissingResourceException;

import es.uji.dsign.crypto.digidoc.DigiDocException;

/**
 * Labels manager for JDigiDoc
 */
public class LabelsManager {
    /** Resource bundle */
    private static ResourceBundle resourceBundle;
    /** singleton instance */
    private static LabelsManager m_instance = null;
    
    /**
     * Singleton accessor
     */
    public static LabelsManager instance() {
        if(m_instance == null)
            m_instance = new LabelsManager();
        return m_instance;
    }
    
    /**
     * LabelsManager default constructor
     */
    private LabelsManager() {
    }
         
    /**
     * Init method for selecting the resource bundle
     * for default locale
     * @param defResBundleName resource bundle base name
     */
    public static void init(String defResBundleName) 
        throws DigiDocException
    {
        try {
            System.out.println("Loading resources from: " + defResBundleName);
            if(defResBundleName.startsWith("jar://")) {
                ClassLoader cl = instance().getClass().getClassLoader();
                InputStream isLabels = cl.getResourceAsStream(defResBundleName.substring(6));
                resourceBundle = new PropertyResourceBundle(isLabels);
                isLabels.close();
            }
            else
                init(defResBundleName, Locale.getDefault());
        } catch(Exception ex) {
            throw new DigiDocException(DigiDocException.ERR_INIT_LABELS, 
                "Error loading labels from: " + defResBundleName, null);
        }
    }

    /**
     * Init method for selecting the resource bundle
     * for specific language and country
     * @param defResBundleName resource bundle base name
     * @param language language name
     * @param country country name
     */
    public static void init(String defResBundleName, String language, String country) {
        Locale locale = new Locale(language, country);
        init(defResBundleName, locale);
    }
    
    /**
     * Init method for selecting the resource bundle for specific locale
     * @param defResBundleName resource bundle base name
     * @param locale java.util.Locale object
     */
    public static void init(String defResBundleName, Locale locale) {     
        resourceBundle = ResourceBundle.getBundle(defResBundleName, locale);
    }    
    
    
    /**
     * Retrieves the label for the spcified key
     * using the current locale / selected resource bundle
     */
    public String getLabel(String key) {
        String value = null;
        try {
            value = resourceBundle.getString(key);
        } catch (MissingResourceException e) {
            //value = (String)m_labels.get(key);
        } 
        return value;        
    }

}
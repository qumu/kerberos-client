package com.qumu.kerberos.client.httpclient;

import org.apache.http.auth.AuthScheme;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.protocol.HttpContext;

public class CustomSPNegoSchemeFactory extends SPNegoSchemeFactory {

	private ServiceNameSource serviceNameSource;
	private String spnPrincipal;
	
	public CustomSPNegoSchemeFactory(ServiceNameSource serviceNameSource, String spnPrincipal, final boolean stripPort, final boolean useCanonicalHostname) {
	   super(stripPort, useCanonicalHostname);
	   this.spnPrincipal = spnPrincipal;
	   this.serviceNameSource = serviceNameSource;
	}

    @Override
    public AuthScheme create(final HttpContext context) {
        return new CustomSPNegoScheme(spnPrincipal, serviceNameSource, super.isStripPort(), super.isUseCanonicalHostname());
    }
}

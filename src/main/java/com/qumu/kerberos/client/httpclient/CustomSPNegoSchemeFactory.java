package com.qumu.kerberos.client.httpclient;

import org.apache.http.auth.AuthScheme;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.protocol.HttpContext;

public class CustomSPNegoSchemeFactory extends SPNegoSchemeFactory {

	private ServiceNameType serviceNameType;
	private String principal;

	public CustomSPNegoSchemeFactory(ServiceNameType serviceNameType, String principal, final boolean stripPort, final boolean useCanonicalHostname) {
	   super(stripPort, useCanonicalHostname);
	   this.principal = principal;
	   this.serviceNameType = serviceNameType;
	}

    @Override
    public AuthScheme create(final HttpContext context) {
        return new CustomSPNegoScheme(principal, serviceNameType, super.isStripPort(), super.isUseCanonicalHostname());
    }
}

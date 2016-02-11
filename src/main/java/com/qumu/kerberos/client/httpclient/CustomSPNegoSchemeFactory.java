package com.qumu.kerberos.client.httpclient;

import org.apache.http.auth.AuthScheme;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.protocol.HttpContext;

public class CustomSPNegoSchemeFactory extends SPNegoSchemeFactory {

	private ServiceNameType serviceNameType;
	private String userPrincipal;
	private String servicePrincipal;

	public CustomSPNegoSchemeFactory(ServiceNameType serviceNameType, String userPrincipal, final boolean stripPort, final boolean useCanonicalHostname) {
		this(serviceNameType, userPrincipal, null, stripPort, useCanonicalHostname);
	}

	public CustomSPNegoSchemeFactory(ServiceNameType serviceNameType, String userPrincipal, String servicePrincipal, final boolean stripPort, final boolean useCanonicalHostname) {
		   super(stripPort, useCanonicalHostname);
		   this.userPrincipal = userPrincipal;
		   this.servicePrincipal = servicePrincipal;
		   this.serviceNameType = serviceNameType;
	}

    @Override
    public AuthScheme create(final HttpContext context) {
        return new CustomSPNegoScheme(userPrincipal, servicePrincipal, serviceNameType, super.isStripPort(), super.isUseCanonicalHostname());
    }
}

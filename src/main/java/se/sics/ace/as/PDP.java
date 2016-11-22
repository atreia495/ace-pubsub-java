/*******************************************************************************
 * Copyright (c) 2016, SICS Swedish ICT AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.as;

import se.sics.ace.AceException;

/**
 * An interface for the Policy Decision Point that this AS uses to make 
 * authorization decisions.
 * 
 * @author Ludwig Seitz
 *
 */
public interface PDP {

	/**
	 * Checks if this client can access the /token endpoint.
	 * 
	 * @param clientId  the identifier of the client.
	 * 
	 * @return  true if the client can access, false otherwise
	 */
	public abstract boolean canAccessToken(String clientId);
	
	/**
	 * Checks if this RS can access the /introspect endpoint.
	 * 
	 * @param rsId  the identifier of the RS.
	 * @return  true if the RS can access, false otherwise
	 */
	public abstract boolean canAccessIntrospect(String rsId);
	
	/**
	 * Checks if the given client can get an access token for the given 
	 * audience and scope.
	 * 
	 * @param clientId  the identifier of the client
	 * @param aud  the audience for which the client request access 
	 * @param scopes  the scope(s) requested for the access token, if present, 
	 * 	           or null. Note that the scopes must be separated by spaces if
	 * 			   there are several
	 * 
	 * @return  The scopes that can be granted or null if access id denied
	 * 
	 *  @throws AceException  
	 */
	public abstract String canAccess(String clientId, String aud, 
				String scopes) throws AceException;
}

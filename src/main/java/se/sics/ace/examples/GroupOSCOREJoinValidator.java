/*******************************************************************************
 * Copyright (c) 2018, RISE SICS AB
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
package se.sics.ace.examples;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.ScopeValidator;

/**
 * Simple audience and scope validator for testing purposes.
 * This validator expects the scopes to be Strings as in OAuth 2.0.
 * 
 * The actions are expected to be integers corresponding to the 
 * values for RESTful actions in <code>Constants</code>.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class GroupOSCOREJoinValidator implements AudienceValidator, ScopeValidator {

    /**
     * The audiences we recognize
     */
	private Set<String> myAudiences;
	
	/**
     * The audiences acting as OSCORE Group Managers
     * Each of these audiences is also included in the main set "myAudiences"
     */
	private Set<String> myGMAudiences;
	
	/**
	 * Maps the scopes to a map that maps the scope's resources to the actions 
	 * allowed on that resource
	 */
	private Map<String, Map<String, Set<Short>>> myScopes;  
	
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 * @param myScopes  the scopes that this validator should accept
	 */
	public GroupOSCOREJoinValidator(Set<String> myAudiences, 
	        Map<String, Map<String, Set<Short>>> myScopes) {
		this.myAudiences = new HashSet<>();
		this.myGMAudiences = new HashSet<>();
		this.myScopes = new HashMap<>();
		if (myAudiences != null) {
		    this.myAudiences.addAll(myAudiences);
		} else {
		    this.myAudiences = Collections.emptySet();
		}
		if (myScopes != null) {
		    this.myScopes.putAll(myScopes);
		} else {
		    this.myScopes = Collections.emptyMap();
		}
	}
	
	// M.T.
	/**
	 * Set the list of audiences acting as OSCORE Group Managers.
	 * Check that each of those audiences are in the main set "myAudiences"
	 * 
	 * @param myGMAudiences  the audiences that this validator considers as OSCORE Group Managers
	 */
	public void setGMAudiences(Set<String> myGMAudiences) throws AceException {
		if (myGMAudiences != null) {
			for (String foo : myGMAudiences) {
				if (!myAudiences.contains(foo))
					throw new AceException("This OSCORE Group Manager is not an accepted audience");
				else this.myGMAudiences.add(foo);
			}
		} else {
		    this.myGMAudiences = Collections.emptySet();
		}
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

    @Override
    public boolean scopeMatch(CBORObject scope, String resourceId, Object actionId)
            throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String in KissValidator");
        }
        String[] scopes = scope.AsString().split(" ");
        for (String subscope : scopes) {
            Map<String, Set<Short>> resources = this.myScopes.get(subscope);
            if (resources == null) {
                continue;
            }
            if (resources.containsKey(resourceId)) {
                if (resources.get(resourceId).contains(actionId)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String in KissValidator");
        }
        String[] scopes = scope.AsString().split(" ");
        for (String subscope : scopes) {           
            Map<String, Set<Short>> resources = this.myScopes.get(subscope);
            if (resources.containsKey(resourceId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isScopeMeaningful(CBORObject scope) throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String if no audience is specified");
        }
        return this.myScopes.containsKey(scope.AsString());
    }
    
    @Override
    public boolean isScopeMeaningful(CBORObject scope, ArrayList<String> aud) throws AceException {
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
    	boolean scopeMustBeBinary = false;
    	boolean rsOSCOREGroupManager = false;
    	for (String foo : aud) {
    		if (myGMAudiences.contains(foo)) {
    			rsOSCOREGroupManager = true;
    			break;
    		}
    	}
    	scopeMustBeBinary = rsOSCOREGroupManager;
        
        if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		throw new AceException("Scope for this audience must be a byte string");
        	
        	return this.myScopes.containsKey(scope.AsString());
        	// The audiences are silently ignored
        }
        	
        else if (scope.getType().equals(CBORType.ByteString) && rsOSCOREGroupManager) {
        	
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes((byte[])rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
        	if (cborScope.size() != 2)
        		throw new AceException("Scope must have two elements, i.e. Group ID and list of roles");
        	
        	// Retrieve the Group ID of the OSCORE group
      	  	CBORObject scopeElement = cborScope.get(0);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		scopeStr = scopeElement.AsString();
      	  	}
      	  	else {throw new AceException("The Group ID must be a CBOR Text String");}
        	
      	  	// Retrieve the role or list of roles
      	  	scopeElement = cborScope.get(1);
      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
      	  		// Only one role is specified
      	  		scopeStr = scopeStr + "_" + scopeElement.AsString();
      	  	}
      	  	else if (scopeElement.getType().equals(CBORType.Array)) {
      	  		// Multiple roles are specified
      	  		if (scopeElement.size() < 2) {
      	  			throw new AceException("The CBOR Array of roles must include at least two roles");
      	  		}
      	  		for (int i=0; i<scopeElement.size(); i++) {
      	  			if (scopeElement.get(i).getType().equals(CBORType.TextString)) {
      	  			scopeStr = scopeStr + "_" + scopeElement.get(i).AsString();
      	  			}
      	  			else {throw new AceException("The roles must be CBOR Text Strings");}
      	  		}
      	  	}
      	  	else {throw new AceException("Invalid format of roles");}
      	  	
        	return this.myScopes.containsKey(scopeStr);
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the audience is not related to an OSCORE Group Manager.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
        
        return false;
        
    }
}

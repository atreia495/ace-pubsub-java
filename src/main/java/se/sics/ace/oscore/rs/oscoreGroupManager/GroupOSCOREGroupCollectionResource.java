 /*******************************************************************************
 * Copyright (c) 2019, RISE AB
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
package se.sics.ace.oscore.rs.oscoreGroupManager;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.Bytes;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;
import se.sics.ace.rs.TokenRepository;

/**
 * Definition of the Group OSCORE group-collection resource
 */
public class GroupOSCOREGroupCollectionResource extends CoapResource {
	
	private Map<String, GroupOSCOREGroupConfigurationResource> groupConfigurationResources = new HashMap<>();
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	private GroupOSCOREValidator valid;
	
	private final String asUri = new String("coap://as.example.com/token");
	
    private final static String rootGroupMembershipResourcePath = "ace-group";
    
    private final static String groupCollectionResourcePath = "admin";
		
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     * @param myScopes  the scopes of this OSCORE Group Manager
     * @param valid  the access validator of this OSCORE Group Manager
     */
    public GroupOSCOREGroupCollectionResource(String resId,
    										  Map<String, GroupInfo> existingGroupInfo,
    										  Map<String, Map<String, Set<Short>>> myScopes,
    										  GroupOSCOREValidator valid) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group Collection Resource " + resId);
     
        this.existingGroupInfo = existingGroupInfo;
        this.myScopes = myScopes;
        this.valid = valid;
        
        // TODO: remove
        // ============
        // Force the presence of an already existing group configuration for early testing
        GroupOSCOREGroupConfigurationResource testConf = new GroupOSCOREGroupConfigurationResource(
        													"gp500", CBORObject.NewMap(),
        													this.groupConfigurationResources,
        													this.existingGroupInfo,
        													this.myScopes, this.valid);
        testConf.getConfigurationParameters().Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp500"));
        this.groupConfigurationResources.put("gp500", testConf);
        // ============
        
    }

    @Override
    public synchronized void handleGET(CoapExchange exchange) {
    	
    	System.out.println("GET request reached the GM at /" + groupCollectionResourcePath);
        
    	// Process the request for retrieving the full list of Group Configurations
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
    	
    	String auxString = new String("");
    	
    	for (String groupName : this.groupConfigurationResources.keySet()) {
    		boolean selected = false;
    		
    		for (int i = 0; i < permissionSetToken.length; i++) {
    			if (Util.matchingGroupOscoreName(groupName, permissionSetToken[i].get(0))) {
    				try {
        				int permissions = permissionSetToken[i].get(1).AsInt32();
    					if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST)) {
    						// One match has been found
    						selected = true;
    						break;
    					}
					} catch (AceException e) {
						System.err.println("Error while checking the group name against the group name pattern: " + e.getMessage());
					}
    			}
    		}
    		
    		if (selected == false) {
    			// Move to the next group-configuration resource
    			continue;
    		}
    		
    		// This group configuration has passed the filtering and has been selected
    		if (auxString.equals("") == false) {
    			auxString += ",";
    		}
    		
    		auxString += "<" + request.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
    	}
    	
    	// Respond to the request for retrieving the full list of Group Configurations

    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);

    	if (this.existingGroupInfo.size() != 0) {
        	byte[] responsePayload = auxString.getBytes(Constants.charset);
        	coapResponse.setPayload(responsePayload);
    		coapResponse.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    	}

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handleFETCH(CoapExchange exchange) {

    	System.out.println("FETCH request reached the GM at /" + groupCollectionResourcePath);
        
    	// Process the request for retrieving a list of Group Configurations by filters
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
    		System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
    	
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
        	errorString = new String("A payload must be present");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}

    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
        	errorString = new String("Invalid payload format");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
            	errorString = new String("Invalid format of paramemeter with CBOR abbreviation: " + key.AsInt32());
        		System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
    	}
    	
    	String auxString = new String("");
    	
    	for (String groupName : this.groupConfigurationResources.keySet()) {
    		
			boolean selected = false;
    		
		    for (int i = 0; i < permissionSetToken.length; i++) {
		        if (Util.matchingGroupOscoreName(groupName, permissionSetToken[i].get(0))) {
		            try {
			            int permissions = permissionSetToken[i].get(1).AsInt32();
		                if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST)) {
		                    // One match has been found
		                    selected = true;
		                    break;
		                }
		            } catch (AceException e) {
		                System.err.println("Error while checking the group name against the group name pattern: " + e.getMessage());
		            }
		        }
		    }
		    
		    if (selected == false) {
		        // Move to the next group-configuration resource
		        continue;
		    }
		    
			CBORObject configurationParameters = this.groupConfigurationResources.get(groupName).getConfigurationParameters();
		    
    		// Perform the filtering based on the specified filter criteria
    		for (CBORObject elemKey : requestCBOR.getKeys()) {
    			
    			// The parameter in the filter must be present in the configuration
    			if (configurationParameters.ContainsKey(elemKey) == false) {
    				selected = false;
    				break;
    			}
    			
    			if (requestCBOR.get(elemKey).equals(configurationParameters.get(elemKey)) == false) {
					selected = false;
					break;
    			}
    			
    		}
    		
			if (selected == true) {
    			// This group configuration has passed the filtering and has been selected
	    		if (auxString.equals("") == false) {
	    			auxString += ",";
	    		}
        		auxString += "<" + request.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
			}

    	}
    	
    	
    	// Respond to the request for retrieving a list of Group Configurations by filters
        
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);

    	if (this.existingGroupInfo.size() != 0) {
        	byte[] responsePayload = auxString.getBytes(Constants.charset);
        	coapResponse.setPayload(responsePayload);
    		coapResponse.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    	}

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handlePOST(CoapExchange exchange) {
        
    	System.out.println("POST request reached the GM at /" + groupCollectionResourcePath);
    	
    	// Process the request for creating a new Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
    	// Check that at least one scope entry in the access token allows the "Create" admin permission
        boolean permitted = false;
    	CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (adminScopeEntries == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
    	for (int i = 0; i < adminScopeEntries.length; i++) {
    		try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32(); 
        		permitted = Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
			} catch (AceException e) {
				System.err.println("Error while verifying the admin permissions: " + e.getMessage());
			}
    		if (permitted) {
    			break;
    		}
    	}
    	if (!permitted) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
    	
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
        	errorString = new String("A payload must be present");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}

    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
        	errorString = new String("Invalid payload format");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// The payload of the request must include the status parameter 'group_name'
    	if (!requestCBOR.getKeys().contains(GroupcommParameters.GROUP_NAME)) {
    		errorString = new String("The status parameter 'group_name' must be present");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// The payload of the request must not include:
    	// - The status parameters 'rt', 'ace_groupcomm_profile', and 'joining_uri'
    	// - The parameters 'conf_filter' and 'app_groups_diff', as not pertaining to this request
    	if (requestCBOR.getKeys().contains(GroupcommParameters.RT) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.ACE_GROUPCOMM_PROFILE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.JOINING_URI) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.CONF_FILTER) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.APP_GROUPS_DIFF)) {
    		errorString = new String("Invalid set of parameters in the request");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// This Group Manager does not support RSA an signature algorithm
    	if (requestCBOR.getKeys().contains(GroupcommParameters.SIGN_ALG)) {
    		CBORObject signAlg = requestCBOR.get(GroupcommParameters.SIGN_ALG);
    		if (signAlg.equals(AlgorithmID.RSA_PSS_256.AsCBOR()) ||
    			signAlg.equals(AlgorithmID.RSA_PSS_384.AsCBOR()) ||
    			signAlg.equals(AlgorithmID.RSA_PSS_512.AsCBOR())) {
    			
    		}
    		CBORObject myResponse = CBORObject.NewMap();
    		errorString = new String("RSA is not supported as signature algorithm");
    		myResponse.Add(GroupcommParameters.ERROR, GroupcommErrors.UNSUPPORTED_GROUP_CONF);
    		myResponse.Add(GroupcommParameters.ERROR_DESCRIPTION, errorString);
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE, myResponse.EncodeToBytes(), Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
    			errorString = new String("Malformed or unrecognized paramemeter with CBOR abbreviation: " + key.AsInt32());
    			System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
    	}

    	CBORObject ret = createNewGroupConfiguration(request, adminScopeEntries);
    	    	
    	// Respond to the request for creating a new Group Configuration
        
    	ResponseCode responseCode = CoAP.ResponseCode.valueOf(ret.get(0).AsInt32());
    	Response coapResponse = new Response(responseCode);
    	if (ret.get(1) != null) {
    		int contentFormat = ret.get(1).AsInt32();
        	coapResponse.getOptions().setContentFormat(contentFormat);
    	}
    	byte[] responsePayload = null;
    	if (ret.get(2) == null) {
    		responsePayload = Bytes.EMPTY;
    	}
    	else if (ret.get(2).getType() == CBORType.Map) {
    		responsePayload = ret.get(2).EncodeToBytes();
    	}
    	else if (ret.get(2).getType() == CBORType.TextString) {
    		responsePayload = ret.get(2).AsString().getBytes(Constants.charset);
    	}
    	coapResponse.setPayload(responsePayload);

    	exchange.respond(coapResponse);
    	
    }
    
	/**
     * Create a new group-configuration resource
     * 
     * @param requestCBOR  the POST request to the group-collection resource
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  a CBOR array with three elements, in this order
     * 			- The CoAP response code for the response to the Administrator, as a CBOR integer
     * 			- The CoAP Content-Format to use in the response to the Administrator, as a CBOR integer. It can be null
     * 			- The payload for the response to the Administrator, as a CBOR map or a CBOR text string. It can be null
     * 
     */
    private CBORObject createNewGroupConfiguration(final Request request, final CBORObject[] adminScopeEntries) {
    	
    	String groupName = null;
    	CBORObject ret = CBORObject.NewArray();
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(request.getPayload());

    	// Build a preliminary group configuration, with the final name still to be determined
    	CBORObject buildOutput = GroupOSCOREGroupConfigurationResource.buildGroupConfiguration(requestCBOR, null);
    	
    	// In case of failure, return the information to return an error response to the Administrator
    	if (buildOutput.size() == 3) {

    		for (int i = 0; i < buildOutput.size(); i++) {
    			ret.Add(buildOutput.get(i));
    		}
    		return ret;
    	}
    	
    	// Determine the group name to use
    	String proposedName = requestCBOR.get(GroupcommParameters.GROUP_NAME).AsString();
    	groupName = allocateGroupName(proposedName, adminScopeEntries);
    	
    	if (groupName == null) {
    		// No available and suitable name could be allocated for the new group.
    		//
    		// Return the information for replying with an error response.
    		ret.Add(CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value);
    		ret.Add(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		CBORObject payloadCBOR = CBORObject.NewMap();
    		payloadCBOR.Add(GroupcommParameters.ERROR, GroupcommErrors.GROUP_NAME_NOT_DETERMINED);
    		ret.Add(payloadCBOR);
    		return ret;
    	}
    	
    	// The new name is available and suitable. Add the group configuration to the collection
    	
    	// Complete the group configuration with the selected group name
    	CBORObject groupConfiguration = buildOutput.get(3);
    	groupConfiguration.Add(GroupcommParameters.GROUP_NAME, groupName);
    	
    	// Complete the group configuration with the URI of the associated group-membership resource
    	String requestUri = request.getURI();
    	int index = requestUri.lastIndexOf(super.getURI());
    	String baseUri = request.getURI().substring(0, index + 1);
    	String joiningUri = baseUri + rootGroupMembershipResourcePath + "/" + groupName;
    	groupConfiguration.Add(GroupcommParameters.JOINING_URI, joiningUri);
    	
    	// Complete the group configuration with the URI of the associated Authorization Server
    	groupConfiguration.Add(GroupcommParameters.AS_URI, this.asUri);
    	
    	// Create the internal GroupInfo data structure first
    	// TODO
    	
    	GroupOSCOREGroupConfigurationResource newGroupConfigurationResource = null;
    	
    	synchronized(groupConfigurationResources) {
            newGroupConfigurationResource =  new GroupOSCOREGroupConfigurationResource(groupName, groupConfiguration,
            																		   this.groupConfigurationResources,
														  							   this.existingGroupInfo, this.myScopes,
														  							   this.valid);
            groupConfigurationResources.put(groupName, newGroupConfigurationResource);
            	
    	}

    	Set<Short> actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.FETCH);
    	actions.add(Constants.PUT);
    	actions.add(Constants.PATCH);
    	actions.add(Constants.iPATCH);
    	actions.add(Constants.DELETE);
    	this.myScopes.get(groupCollectionResourcePath).put(groupCollectionResourcePath + "/" + groupName, actions);
    	
    	try {
			valid.setGroupAdminResources(Collections.singleton(groupCollectionResourcePath + "/" + groupName));
		} catch (AceException e) {
			groupConfigurationResources.remove(groupName); // rollback
			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName); // rollback
			
			String errorString = new String ("Error while initializing the group-configuration resource");			
    		ret.Add(CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value);
    		ret.Add(null);
    		CBORObject payloadCBOR = CBORObject.FromObject(errorString);
    		ret.Add(payloadCBOR);
    		System.err.println(errorString + "\n" + e.getMessage());
    		return ret;
		}

    	this.add(newGroupConfigurationResource);
    	
    	
    	// Create the group-membership resource and make it actually accessible
    	// TODO
    	
    	// Finalize the payload for the response to the Administrator
    	
    	CBORObject finalPayloadCBOR = CBORObject.NewMap();
    	
    	finalPayloadCBOR = buildOutput.get(2);    	
    	finalPayloadCBOR.Add(GroupcommParameters.GROUP_NAME, groupName);
    	finalPayloadCBOR.Add(GroupcommParameters.JOINING_URI, joiningUri);
    	finalPayloadCBOR.Add(GroupcommParameters.AS_URI, this.asUri);
    	
    	ret.Add(buildOutput.get(0));
    	ret.Add(buildOutput.get(1));
    	ret.Add(finalPayloadCBOR);
    	
    	return ret;
    	
    }

	/**
     * Try to find an alternative name for a new group to be created
     * 
     * @param proposedGroupName  the group name originally proposed in the POST request from the Administrator
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  the new, alternative name to assign to the group, or null if it was not possible to determine one
     * 
     */
    private String allocateGroupName(final String proposedGroupName, final CBORObject[] adminScopeEntries) {
    	
    	String newName = null;
    	
    	synchronized (groupConfigurationResources) {
    		
        	if (!groupConfigurationResources.containsKey(proposedGroupName)) {
        		// The proposed name is available.
        		
        		// Check if there is at least one scope entry such that the name matches the name pattern
        		// and the set of permissions includes the "Create" admin permission
        		boolean permitted = false;
        		
        		for (int i = 0; i < adminScopeEntries.length; i++) {
        		    try {
        		        short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
        		        if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE)) {
        		        	permitted = Util.matchingGroupOscoreName(proposedGroupName, adminScopeEntries[i].get(0));
        		        }
        		    } catch (AceException e) {
        		        System.err.println("Error while verifying the admin permissions: " + e.getMessage());
        		    }
        		    if (permitted) {
        		        break;
        		    }
        		}
        		if (permitted) {
	        		// Reserve the proposed name, by adding a dummy entry
	        		// in the collection of group-configuration resources
	        		newName = new String(proposedGroupName);
	        		groupConfigurationResources.put(newName, null);
	        		return newName;
        		}
        	}
        	// The proposed name is not available. Try to find a new one.
        	
        	// TBD
    		
    	}
    	
    	return newName;
    	
    }

}

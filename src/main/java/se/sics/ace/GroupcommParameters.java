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
package se.sics.ace;

import java.util.HashSet;
import java.util.Set;

/**
 * Constants for use with ACE Groupcomm
 * 
 * @author Marco Tiloca
 *
 */

public class GroupcommParameters {
	
    /**
	 * Group OSCORE abbreviations =================================
	 */

    /**
     * The OSCORE group uses only the group mode
     */
    public static final short GROUP_OSCORE_GROUP_MODE_ONLY = 1;
    
    /**
     * The OSCORE group uses both the group mode and the pairwise mode
     */
    public static final short GROUP_OSCORE_GROUP_PAIRWISE_MODE = 2;
    
    /**
     * The OSCORE group uses only the pairwise mode
     */
    public static final short GROUP_OSCORE_PAIRWISE_MODE_ONLY = 3;
    
    
    /**
     * Requester role
     */
    public static final short GROUP_OSCORE_REQUESTER = 1;
    
    /**
     * Responder role
     */
    public static final short GROUP_OSCORE_RESPONDER = 2;
    
    /**
     * Monitor role
     */
    public static final short GROUP_OSCORE_MONITOR = 3;
    
    /**
     * Verifier role
     */
    public static final short GROUP_OSCORE_VERIFIER = 4;
    
    /**
     * Roles as strings
     */
    public static final String[] GROUP_OSCORE_ROLES = {"reserved", "requester", "responder", "monitor", "verifier"};
    
    /**
     * Return a set of integers including the valid Group OSCORE role combinations
	 *
     * @return  the set of valid Group OSCORE combinations
     */
    public static Set<Integer> getValidGroupOSCORERoleCombinations() {

    	Set<Integer> validRoleCombinations = new HashSet<Integer>();
    	
        // Set the valid combinations of roles in a Joining Request
        // Combinations are expressed with the AIF specific data model AIF-OSCORE-GROUPCOMM
        validRoleCombinations.add(1 << GROUP_OSCORE_REQUESTER);   // Requester (2)
        validRoleCombinations.add(1 << GROUP_OSCORE_RESPONDER);   // Responder (4)
        validRoleCombinations.add((1 << GROUP_OSCORE_REQUESTER) +
        		                  (1 << GROUP_OSCORE_RESPONDER)); // Requester+Responder (6)
        validRoleCombinations.add(1 << GROUP_OSCORE_MONITOR);     // Monitor (8)
    	
    	return validRoleCombinations;
    }
	
    /**
     * Admin permission "List"
     */
    public static final short GROUP_OSCORE_ADMIN_LIST = 0;
    
    /**
     * Admin permission "Create"
     */
    public static final short GROUP_OSCORE_ADMIN_CREATE = 1;
    
    /**
     * Admin permission "Read"
     */
    public static final short GROUP_OSCORE_ADMIN_READ = 2;
    
    /**
     * Admin permission "Write"
     */
    public static final short GROUP_OSCORE_ADMIN_WRITE = 3;
    
    /**
     * Admin permission "Delete"
     */
    public static final short GROUP_OSCORE_ADMIN_DELETE = 4;
    
    /**
     * Admin permissions as strings
     */
    public static final String[] GROUP_OSCORE_ADMIN_PERMISSIONS = {"list", "create", "read", "write", "delete"};
    
    
    /**
     * Value for the application profile "coap_group_oscore_app"
     */
    public static final short COAP_GROUP_OSCORE_APP = 1;
    
    
    /**
     * Value for the group key type "Group_OSCORE_Input_Material object"
     */
    public static final short GROUP_OSCORE_INPUT_MATERIAL_OBJECT = 1;
        
    
    /**
	 * CBOR abbreviations for the CoAP Content-Format application/ace-groupcomm+cbor =================================
	 */
    
    // Defined in draft-ietf-ace-key-groupcomm
    
    public static final short ERROR = 0;
    
    public static final short ERROR_DECRIPTION = 1;
    
    public static final short GID = 2;
    
    public static final short GNAME = 3;
    
    public static final short GURI = 4;
    
    public static final short SCOPE = 5;
    
    public static final short GET_CREDS = 6;
    
    public static final short CLIENT_CRED = 7;
    
    public static final short CNONCE = 8;
    
    public static final short CLIENT_CRED_VERIFY = 9;
    
    public static final short CREDS_REPO = 10;
    
    public static final short CONTROL_URI = 11;
    
    public static final short GKTY = 12;
    
    public static final short KEY = 13;
    
    public static final short NUM = 14;
    
    public static final short ACE_GROUPCOMM_PROFILE = 15;
    
    public static final short EXP = 16;
    
    public static final short CREDS = 17;
    
    public static final short PEER_ROLES = 18;
    
    public static final short PEER_IDENTIFIERS = 19;
    
    public static final short GROUP_POLICIES = 20;
    
    public static final short KDC_CRED = 21;
    
    public static final short KDC_NONCE = 22;
    
    public static final short KDC_CRED_VERIFY = 23;
    
    public static final short REKEYING_SCHEME = 24;
    
    public static final short MGT_KEY_MATERIAL = 25;
    
    public static final short CONTROL_GROUP_URI = 26;
    
    public static final short SIGN_INFO = 27;
    
    public static final short KDCCHALLENGE = 28;

    
    // Defined in draft-ietf-ace-key-groupcomm-oscore
    
    public static final short GROUP_SENDER_ID = 29;
    
    public static final short ECDH_INFO = 30;
    
    public static final short KDC_DH_CREDS = 31;
    
    public static final short GROUP_ENC_KEY = 32;
    
    public static final short STALE_NODE_IDS = 33;
    
   
    // Defined in draft-ietf-ace-oscore-gm-admin
    
    public static final short HKDF = 34;
    
    public static final short CRED_FMT = 35;
    
    public static final short GROUP_MODE = 36;
    
    public static final short GP_ENC_ALG = 37;
    
    public static final short SIGN_ALG = 38;
    
    public static final short SIGN_PARAMS = 39;
    
    public static final short PAIRWISE_MODE = 40;
    
    public static final short ALG = 41;
    
    public static final short ECDH_ALG = 42;
    
    public static final short ECDH_PARAMS = 43;
    
    public static final short DET_REQ = 44;
    
    public static final short DET_HASH_ALG = 45;
    
    public static final short RT = 46;
    
    public static final short ACTIVE = 47;
    
    public static final short GROUP_NAME = 48;
    
    public static final short GROUP_TITLE = 49;
    
    public static final short MAX_STALE_SETS = 50;
    
    public static final short GID_REUSE = 51;
    
    public static final short APP_GROUPS = 52;
    
    public static final short JOINING_URI = 53;
    
    public static final short AS_URI = 54;
    
    public static final short CONF_FILTER = 55;
    
    public static final short APP_GROUPS_DIFF = 56;
    
}

#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from java.util import Collections, HashMap, HashSet, ArrayList, Arrays, Date
from org.oxauth.persistence.model.configuration import GluuConfiguration
from org.gluu.persist import PersistenceEntryManager
from java.nio.charset import Charset
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.service import AuthenticationService, SessionIdService
from org.gluu.oxauth.service.common import UserService
from org.gluu.util import StringHelper
from org.gluu.oxauth.service.net import HttpService
from org.json import JSONObject
import base64
import java

from org.gluu.util import StringHelper
from java.lang import String

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        #constants for tasks
        self.task_Verify = 0,
        self.task_Identify = 0x10,
        self.task_Enroll = 0x20,
        self.task_LiveOnly = 0x80,
        self.task_MaxTriesMask = 0x0F,
        self.task_LiveDetection = 0x100,
        self.task_ChallengeResponse = 0x200,
        self.task_AutoEnroll = 0x1000

    def init(self, customScript,  configurationAttributes):

        print "BioID. Initialized successfully"
        self.ENDPOINT = "https://bws.bioid.com/extension/"
        self.APP_IDENTIFIER = "c20b01cc-806a-45ed-8a1f-06347f8edf2c"
        self.APP_SECRET = "sTGF4n4HAkvc2PnJp6CeNUNk"
        self.PARTITION = "11811"
        self.STORAGE = "bws"       
        self.uid_attr = self.getLocalPrimaryKey()
        
        return True   

    def destroy(self, configurationAttributes):
        print "BioID. Destroy"
        print "BioID. Destroyed successfully"
        return True
        
    def getAuthenticationMethodClaims(self, requestParameters):
        return None
        
    def getApiVersion(self):
        return 11

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "BioID. Authenticate "
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        user_name = credentials.getUsername()
        if (step == 1):
            print "BioID. Authenticate for step 1"

            logged_in = False
            userService = CdiUtil.bean(UserService)
            authenticated_user = self.processBasicAuthentication(credentials)
            if authenticated_user == None:
                print "BioID. User does not exist"
                return False
            
            identity.setWorkingParameter("user_name",user_name)
            
            print "user-name ok %s" % user_name
            bcid = self.STORAGE + "." + self.PARTITION + "." + str(String(user_name).hashCode())
            return True
        
        elif step == 2:
            
            auth_method = identity.getWorkingParameter("bioID_auth_method")
            print "BioID. Authenticate method for step 2. bioID_auth_method: '%s'" % auth_method
            
            bcid = self.STORAGE + "." + self.PARTITION + "." + str(String(user_name).hashCode())
            if auth_method == 'enroll':
                # invoke enroll API
                access_token = self.getAccessToken( bcid, "enroll" )
                identity.setWorkingParameter("access_token",access_token)
                self.enroll(access_token)
                return True
            
            elif auth_method == 'authenticate':
                # invoke upload API
                access_token = self.getAccessToken( bcid, "verify" )
                identity.setWorkingParameter("access_token",access_token)
                return True
            
            else:
                return False    
        
        else:
            return False

    
    def prepareForStep(self, configurationAttributes, requestParameters, step):
        identity = CdiUtil.bean(Identity)
        user_name = identity.getWorkingParameter("user_name")
        
        if step == 1:
            print "BioID. Prepare for step 1"
            return True
        elif step == 2:
            auth_method = identity.getWorkingParameter("bioID_auth_method")
            print "BioID. Prepare for step 2 %s" % auth_method
            print "user name %s" % user_name
            bcid = self.STORAGE + "." + self.PARTITION + "." + str(String(user_name).hashCode())
            print "bcid %s" %bcid
            
            if auth_method == 'enroll':
                # invoke verify API
                access_token = self.getAccessToken( bcid, "enroll" )
                print "access_token %s - " % access_token
                identity.setWorkingParameter("access_token",access_token)
                return True
                
            elif auth_method == 'authenticate':
                # invoke upload API
                access_token = self.getAccessToken( bcid, "verify" )
                identity.setWorkingParameter("access_token",access_token)
                return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("bioID_auth_method","access_token","user_name")
    
    
    def getCountAuthenticationSteps(self, configurationAttributes):
        print "BioID. getCountAuthenticationSteps called"
        return 2


    def getPageForStep(self, configurationAttributes, step):
        print "BioID. getPageForStep called %s" % str(step)
        
        if step == 1:
            return ""
        elif step == 2:
            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()
            user_name = credentials.getUsername()
            
            bcid = self.STORAGE + "." + self.PARTITION + "." + str(String(user_name).hashCode())
            is_user_enrolled = self.isenrolled(bcid)
            print "BioID. Get page for step 2. auth_method: '%s'" % is_user_enrolled
            if(is_user_enrolled == True):
                identity.setWorkingParameter("bioID_auth_method","authenticate")
                return "/auth/bioid/bioid.xhtml"
            else:
                identity.setWorkingParameter("bioID_auth_method","enroll")
                return "/auth/bioid/bioid.xhtml"
                
        elif step == 3:
            return "/auth/bioID/bioIDlogin.xhtml"


    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "BioID. getNextStep called %s" % str(step)
        if step > 1:
            return 2

        return -1

    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True

    # Get a BWS token to be used for authorization.
    # bcid - The Biometric Class ID (BCID) of the person
    # forTask - The task for which the issued token shall be used.
    # A string containing the issued BWS token.
    def getAccessToken(self, bcid, forTask):
        
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()

        bioID_service_url = self.ENDPOINT + "token?id="+self.APP_IDENTIFIER+"&bcid="+bcid+"&task=verify"
        encodedString = base64.b64encode((self.APP_IDENTIFIER+":"+self.APP_SECRET).encode('utf-8'))
        bioID_service_headers = {"Authorization": "Basic "+encodedString}

        try:
            http_service_response = httpService.executeGet(http_client, bioID_service_url, bioID_service_headers)
            http_response = http_service_response.getHttpResponse()
        except:
            print "BioID. Unable to obtain access token. Exception: ", sys.exc_info()[1]
            return None

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "BioID. Unable to obtain access token.  Get non 200 OK response from server:", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return None

            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes, Charset.forName("UTF-8"))
            print(response_string)
            httpService.consume(http_response)
            return response_string
        finally:
            http_service_response.closeConnection()
    
    def isenrolled(self, bcid):
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()

        bioID_service_url = self.ENDPOINT + "isenrolled?bcid="+bcid+"&trait=face"
        encodedString = base64.b64encode((self.APP_IDENTIFIER+":"+self.APP_SECRET).encode('utf-8'))
        bioID_service_headers = {"Authorization": "Basic "+encodedString}

        try:
            http_service_response = httpService.executeGet(http_client, bioID_service_url, bioID_service_headers)
            http_response = http_service_response.getHttpResponse()
        except:
            print "BioID. failed to invoke isenrolled API: ", sys.exc_info()[1]
            return None

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "BioID. Face not enrolled.  Get non 200 OK response from server:", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return False

            else: 
                return True
        finally:
            http_service_response.closeConnection()
        
    def getResultAPI(self, token):
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()

        bioID_service_url = self.ENDPOINT + "result?access_token="+token
        encodedString = base64.b64encode((self.APP_IDENTIFIER+":"+self.APP_SECRET).encode('utf-8'))
        bioID_service_headers = {"Authorization": "Basic "+encodedString}

        try:
            http_service_response = httpService.executeGet(http_client, bioID_service_url, bioID_service_headers)
            http_response = http_service_response.getHttpResponse()
        except:
            print "BioID. Unable to obtain access token. Exception: ", sys.exc_info()[1]
            return None

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                print "BioID. Unable to obtain access token.  Get non 200 OK response from server:", str(http_response.getStatusLine().getStatusCode())
                httpService.consume(http_response)
                return None

            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes, Charset.forName("UTF-8"))
            json_response = JSONObject(response_string)
            print(json_response)
            httpService.consume(http_response)
        finally:
            http_service_response.closeConnection()

    def getLocalPrimaryKey(self):
        entryManager = CdiUtil.bean(PersistenceEntryManager)
        config = GluuConfiguration()
        config = entryManager.find(config.getClass(), "ou=configuration,o=gluu")
        #Pick (one) attribute where user id is stored (e.g. uid/mail)
        uid_attr = config.getOxIDPAuthentication().get(0).getConfig().getPrimaryKey()
        print "BIOId. init. uid attribute is '%s'" % uid_attr
        return uid_attr
        
    def processBasicAuthentication(self, credentials):
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)

        user_name = credentials.getUsername()
        user_password = credentials.getPassword()

        logged_in = False
        if StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password):
            logged_in = authenticationService.authenticate(user_name, user_password)

        if not logged_in:
            print "OTP. Process basic authentication. Failed to find user '%s'" % user_name
            return None

        find_user_by_uid = authenticationService.getAuthenticatedUser()
        if find_user_by_uid == None:
            print "OTP. Process basic authentication. Failed to find user '%s'" % user_name
            return None
        
        return find_user_by_uid
    
    
    def enroll(self, token):
        httpService = CdiUtil.bean(HttpService)
        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()
        bioID_service_url = self.ENDPOINT + "enroll"
        bioID_service_headers = {"Authorization": "Bearer "+token}

        try:
            http_service_response = httpService.executeGet(http_client, bioID_service_url, bioID_service_headers)
            http_response = http_service_response.getHttpResponse()
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes, Charset.forName("UTF-8"))
            
            print "Enroll response - %s" % response_string
            httpService.consume(http_response)
            if response_string == "Success":
                return True
            else:
                return False
        except:
            print "BioID. failed to invoke enroll API: ", sys.exc_info()[1]
            return None
            
        finally:
            http_service_response.closeConnection()
# Elisa Viihde API Python implementation
# License: GPLv3
# Author: enyone
# Version: 1.4
# https://github.com/enyone/elisaviihde

import requests
import json
import re
import time
import datetime
import math


class elisaviihde:
    # Init args
    verbose = False
    baseurl = "https://api-viihde-gateway.dc1.elisa.fi"
    external_client_id = 'external'
    external_client_secret = None
    external_api_key = None
    authcode = None
    oauth_data = None
    userinfo = None
    inited = False
    verifycerts = False

    def __init__(self, verbose=False):
        self.verbose = verbose
    
    def set_api_key(self, external_api_key, external_client_secret):
        self.external_client_secret = external_client_secret
        self.external_api_key = external_api_key

    @property
    def oauth_token(self):
        if self.oauth_data is None:
            return None
        return self.oauth_data['access_token']
    
    def get_authcode(self):
        if self.verbose:
            print "Getting authcode..."

        try:
            payload = {
                "client_id": self.external_client_id, "client_secret": self.external_client_secret,
                "response_type": "code", "scopes": []
            }
            headers = {'content-type': 'application/json','apikey': self.external_api_key}
            response = requests.post(
                "{}/auth/authorize/access-code".format(self.baseurl),
                json=payload, headers=headers
            )
            self.authcode = response.json()['code']
            return self.authcode
        except ValueError as err:
            raise Exception("Could not fetch sso token", err)

    def get_oauth_data_with_userpass(self, username, password):
        if self.verbose:
            print "Getting oauth token with authcode and user+pass..."

        payload = {
            'grant_type':'authorization_code', 'username': username, 'password': password,
            "client_id": self.external_client_id, "code": self.authcode
        }
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'apikey': self.external_api_key
        }
        response = requests.post(
            "{}/auth/authorize/access-token".format(self.baseurl),
            data=payload, headers=headers
        )
        self.oauth_data = response.json()

    def get_oauth_data_with_refresh_token(self, refresh_token):
        payload = {
            'grant_type':'refresh_token',"client_id": self.external_client_id,
            "client_secret": self.external_client_secret, "refresh_token": refresh_token
        }
        headers = {'Authorization': 'Bearer '+ refresh_token, 'apikey': self.external_api_key}
        response = requests.post(
            "{}/auth/authorize/access-token".format(self.baseurl),
            data=payload, headers=headers
        )
        response.raise_for_status()
        self.oauth_data = response.json()

    def login(self, username, password):
        self.get_authcode()

        self.get_oauth_data_with_userpass(username, password)
        self.inited = True

    def login_with_refresh_token(self, refresh_token):
        self.get_authcode()

        self.get_oauth_data_with_refresh_token(refresh_token)
        self.inited = True

    def islogged(self):
        return self.oauth_token is not None

    def checklogged(self):
        if not self.islogged():
            raise Exception("Not logged in")

    def checkrequest(self, statuscode):
        if not statuscode == requests.codes.ok:
            raise Exception(
                "API request failed with error code: " + str(statuscode))

    def close(self):
        raise NotImplementedError()
        if self.verbose:
            print "Logging out and closing session..."
        logout = self.session.post(self.baseurl + "/api/user/logout",
                                   headers={
                                       "X-Requested-With": "XMLHttpRequest"},
                                   verify=self.verifycerts)
        self.session.close()
        self.userinfo = None
        self.authcode = None
        self.oauth_data = None
        self.inited = False
        self.checkrequest(logout.status_code)

    def gettoken(self):
        return self.authcode

    def getuser(self):
        return self.userinfo

    def recordings_request(self, endpoint, headers={}, use_v21=True):
        headers.update({
            'Authorization': 'Bearer ' + self.oauth_token,
            'apikey': self.external_api_key
        })
        v21 = 'v=2.1' if use_v21 else ''
        platform = 'external'
        app_version = '1.0'
        response = requests.get(
            "{}{}?{}&platform={}&appVersion={}&page=0&pageSize=10000".format(
                self.baseurl, endpoint, v21, platform, app_version
            ),
            headers=headers
        )
        response.raise_for_status()
        return response

    def getfolders(self, folderid=0):
        self.checklogged()
        if folderid == 0:  # root
            folderid = ''
        else:
            folderid = '/{}'.format(folderid)
        # Get folders
        if self.verbose:
            print "Getting folders..."
        try:
            response = self.recordings_request(
                '/rest/npvr/folders{}'.format(folderid), use_v21=False
            )
        except requests.HTTPError:  # Maybe the non-2.1 api no longer works? Fallback to normal.
            if folderid == '':
                return []
            response = self.recordings_request('/rest/npvr/folders'.format(folderid))

        return response.json()['folders']

    def getfolderstatus(self, folderid=0):
        raise NotImplementedError()
        # Get folder info
        if self.verbose:
            print "Getting folder info..."
        self.checklogged()
        folder = self.session.get(self.baseurl + "/tallenteet/api/folder/" + str(folderid),
                                  headers={
                                      "X-Requested-With": "XMLHttpRequest"},
                                  verify=self.verifycerts)
        self.checkrequest(folder.status_code)
        return folder.json()

    def getrecordings(self, folderid=0, page=None, sortby="startTime", sortorder="desc", status="all"):
        # Get recordings from folder
        self.checklogged()
        if self.verbose:
            print "Getting recordings..."
        response = self.recordings_request('/rest/npvr/recordings/folder/{}'.format(folderid))
        return response.json()['recordings']

    def getprogram(self, programid=0):
        raise NotImplementedError()
        # Parse program information
        self.checklogged()
        if self.verbose:
            print "Getting program info..."
        uridata = self.session.get(
            self.baseurl + "/ohjelmaopas/ohjelma/" + str(programid), verify=self.verifycerts)
        self.checkrequest(uridata.status_code)
        programname = ""
        programdesc = ""
        programsrvc = ""
        programtime = 0
        try:
            for line in uridata.text.split("\n"):
                if "itemprop=\"name\"" in line and "data-programid" in line:
                    programname = re.findall('<h3.*?>(.*?)</h3>', line)[0]
                elif "itemprop=\"description\"" in line:
                    programdesc = re.findall('<p.*?>(.*?)</p>', line)[0]
                elif "itemprop=\"name\"" in line:
                    programsrvc = re.findall('<p.*?>(.*?)</p>', line)[0]
                elif "itemprop=\"startDate\"" in line:
                    programtimestr = re.findall(
                        '<span.*?>(.*?)</span>', line)[0]
                    programtime = int(datetime.datetime.fromtimestamp(
                        time.mktime(time.strptime(programtimestr,
                                                  "%d.%m.%Y %H:%M"))).strftime("%s"))
                    programtime = programtime * 1000
        except Exception as exp:
            print "ERROR:", str(exp)
        except Error as exp:
            print "ERROR:", str(exp)

        return {"name": programname, "description": programdesc, "serviceName": programsrvc, "startTimeUTC": programtime}

    def getstreamuri(self, programid=0):
        # Parse recording stream uri for program
        self.checklogged()
        if self.verbose:
            print "Getting stream uri info..."
        response = self.recordings_request("/rest/npvr/recordings/url/{}".format(programid))
        return response.json()['url']

    def markwatched(self, programid=0):
        raise NotImplementedError()
        # Mark recording as watched
        if self.verbose:
            print "Marking as watched..."
        self.checklogged()
        watched = self.session.get(self.baseurl + "/tallenteet/api/watched/" + str(programid),
                                   headers={
                                       "X-Requested-With": "XMLHttpRequest"},
                                   verify=self.verifycerts)
        self.checkrequest(watched.status_code)

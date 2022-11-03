import logging
import requests

__author__ = "Jouni Lehto"
__versionro__="0.1.1"

class Polaris:

    def __init__(self, baseUrl, token, email=None, password=None):
        self.baseUrl = baseUrl
        self.token = token
        self.session = None
        self.email = email
        self.password = password

    def getJwt(self):
        endpoint = self.baseUrl + '/api/auth/v1/authenticate'
        headers = { 'Accept' : 'application/json', 'Content-Type' : 'application/x-www-form-urlencoded' }
        if self.token != None:
            params = { 'accesstoken' : self.token }
        else:
            params = { 'email' : self.email, 'password' : self.password }
        response = requests.post(endpoint, headers=headers, data=params)
        if response.status_code != 200: logging.ERROR(response.json()['errors'][0])
        return response.json()['jwt']

    def createSession(self):
        jwt = self.getJwt()
        headers = { 'Authorization' : 'Bearer ' + jwt, 'Content-Type' : 'application/vnd.api+json' }
        session = requests.Session()
        session.headers.update(headers)
        return session


    # Get the projectID with the project name and
    # branchId with the given branchName and projectId
    # PARAMS: 
    #   projectName = The Project name in Polaris
    #   branchName = The Branch name in Polaris
    def getProjectandBranchIds(self, projectName, branchName):
        if not self.session: self.session = self.createSession()
        endpoint = f"{self.baseUrl}/api/common/v0/projects"
        params = dict([
            ('page[limit]', 10),
            ('filter[project][name][eq]', projectName)
        ])
        response = self.session.get(endpoint, params=params)
        if response.status_code != 200: logging.error(response.json()['errors'][0])

        if response.json()['meta']['total'] == 0:
            logging.error(f'FATAL: project {projectName} not found')
        projectId = response.json()['data'][0]['id']
        # Get the project banchid with projectid and given branchName if given
        branchId = None
        if branchName:
            endpoint = f"{self.baseUrl}/api/common/v0/branches"
            params = dict([
                ('page[limit]', 10),
                ('filter[branch][project][id][eq]', projectId),
                ('filter[branch][name][eq]', branchName)
            ])
            response = self.session.get(endpoint, params=params)
            if response.status_code != 200: logging.error(response.json()['errors'][0])
            if response.json()['meta']['total'] == 0:
                logging.error(f'FATAL: branch {branchName} not found')
            branchId = response.json()['data'][0]['id']
        return projectId, branchId


# -*- coding: utf-8 -*-
#
# Script for triggering CodeDX connectors to start collect
# data from the sources
#
# Used endpoints:
# Get Project ID with project name
#   api/projects/query
# Get connectors for project by project ID
#   api/tool-connector-config/entries
# Trigger connector
#   api/tool-connector-config/entries/project_id/connector_id/analysis
# Check the status for the job-id
#   /api/jobs/job_id
# Sending file for analysis
# /api/projects/<project id>/analysis

import requests
import argparse
import logging
import polling
import os
from blackduck.HubRestApi import HubInstance
import json
from polarisUtility import Polaris

__author__ = "Jouni Lehto"
__versionro__ = "0.1.2"

def getHeader():
    return {
            'API-Key': args.apikey, 
            'Accept': '*/*',
            'Content-Type': '*/*'
        }

def sendFileForAnalysis(project_id, filename):
    if not os.path.exists(filename):
        logging.info("File: " + filename + " not found!")
        return
    header =  {
            'API-Key': args.apikey, 
            'Accept': '*/*'
        }
    response = requests.post(f'{args.url}/codedx/api/projects/{project_id}/analysis', headers=header,
                files={"file": open(filename, 'rb')})

    if response.status_code == 200 or response.status_code == 202:
        logging.info("File: " + filename + " has been sent!")
        return response.json()['jobId']

def getProjectIdByName():
    codedx_filter = {"filter": {"name": args.project}}
    response = requests.post(f'{args.url}/codedx/api/projects/query', headers=getHeader(), json=codedx_filter)
    if response.status_code == 200:
        for project in response.json():
            if project['name'] == args.project:
                if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                    logging.debug(project)
                return project['id']
        # If project list is is empty or not contain exact the same project name than given as repository
        logging.error("Project: " + args.project + " not found!")
    else:
        logging.error(response)

def getProjectIdByTags(tags):
    codedx_filter = {"filter": { "metadata": { args.tag: tags}}}
    response = requests.post(f'{args.url}/codedx/api/projects/query', headers=getHeader(), json=codedx_filter)
    if response.status_code == 200:
        for project in response.json():
            for metadata in project['metadata']:
                if metadata['name'] == args.tag and metadata['value'].strip() == args.project:
                    if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                        logging.debug(project)
                    return project['id']
        # If project list is is empty or not contain exact the same project name than given as repository
        logging.error("Project: " + args.project + " not found!")
    else:
        logging.error(response)

# options: "ASoC","AppScan Enterprise","Aqua CSP","Black Duck Binary Analysis","Black Duck Hub","Burp Enterprise","Checkmarx","Checkmarx IAST","CodeSonar",
#          "Contrast","Coverity","Data Theorem Mobile","DefenseCode ThunderScan","Dependency-Track","Fortify Software Security Center","GitHub Advanced Security",
#          "JFrog Xray","Netsparker Enterprise","NowSecure","Polaris","Prisma Cloud (RedLock)","Prisma Cloud Compute (Twistlock)","Qualys VM","Qualys WAS",
#          "Rapid7 InsightAppSec","SD Elements","Seeker","Snyk","SonarQube","Sonatype Nexus","Synopsys Managed Services Platform","Tenable.io","Tenable.io Web App Scanning",
#          "Tenable.sc","Tinfoil API","Tinfoil Web","Trustwave App Scanner","Veracode","WhiteHat Sentinel","WhiteSource"
def getProjectCollectorIDs(project_id, collector_types):
    response = requests.get(f'{args.url}/codedx/api/tool-connector-config/entries/{project_id}', headers=getHeader())
    if response.status_code == 200:
        collectorIds = []
        for data in response.json():
            if args.collector_type == "ALL":
                collectorIds.append({"name": data["name"], "id": data["id"]})
            elif data["tool"].lower() in collector_types.lower():
                if args.collector_name:
                    if args.collector_name.lower() == data["name"].lower():
                        collectorIds.append({"name": data["name"], "id": data["id"]})
                        return collectorIds
                else:
                    collectorIds.append({"name": data["name"], "id": data["id"]})
        return collectorIds
    return []

def triggerCollectors(project_id, collector):
    logging.debug(f'Triggering collector: {collector["name"]} with id {collector["id"]}')
    response = requests.post(f'{args.url}/codedx/api/tool-connector-config/entries/{project_id}/{collector["id"]}/analysis', headers=getHeader())
    if response.status_code == 200:
        return response.json()['jobId']
    else:
        logging.error(response)

def checkStatus(job_id):
    response = requests.get(f'{args.url}/codedx/api/jobs/{job_id}', headers=getHeader())
    return response

def checkSuccess(response):
    if response.status_code == 200:
        if response.json()['status'] == "completed":
            return True
        else:
            if args.filename:
                logging.info("File analysis is still going on, status: " + response.json()['status'])
            else:
                logging.info("Analysis was not ready yet, status: " + response.json()['status'])
    return False

def createProject(project_name):
    codedx_data = { "name": project_name }
    response = requests.put(f'{args.url}/codedx/api/projects', headers=getHeader(), json=codedx_data)
    if response.status_code == 201:
        project_id = response.json()['id']
        logging.info("Project: " + project_name + " created!")
        return project_id
    else:
        logging.error("Project: " + project_name + " creation failed!")

def addCoverityCollector(project_id, project_name, branch_name):
    global args
    if project_id:
        codedx_data = { "tool": "Coverity", "name": "Coverity Connector" }
        response = requests.post(args.url + "/api/tool-connector-config/entries/" + str(project_id), headers=getHeader(), json=codedx_data)
        if response.status_code == 201:
            collector_id = response.json()['id']
            if collector_id:
                codedx_data = { "server_url": args.collector_url, "username": args.collector_username, "password": args.collector_password \
                    , "selected_project": project_name, "selected_stream": branch_name \
                    , "ingest_all_components": False, "available-during-analysis": True, "component": [args.application + ".Other"]}
                response = requests.put(args.url + "/api/tool-connector-config/values/" + str(collector_id), headers=getHeader(), json=codedx_data)
                if response.status_code == 200:
                    logging.info("Project: " + project_name + " Coverity Collector added!")
                else:
                    logging.error(response.content)
                    logging.error("Project: " + project_name + " Coverity Collector adding failed!")

def addBlackDuckCollector(project_id, project_name):
    global args
    if project_id:
        codedx_data = { "tool": "Black Duck Hub", "name": "Black Duck Connector" }
        response = requests.post(args.url + "/api/tool-connector-config/entries/" + str(project_id), headers=getHeader(), json=codedx_data)
        if response.status_code == 201:
            collector_id = response.json()['id']
            if collector_id:
                codedx_data = { "server_url": args.collector_url, "auth_type": "api_token" \
                    , "api_key": args.collector_apikey, "project": getBDProjectIDByName(project_name), "version": "cdx_use_latest_ver" \
                    , "bom_custom_fields": False, "omp_custom_fields": False, "comp_ver_custom_fields": False, "license_risks": True \
                    , "matched_files": True, "operational_risks": False, "security_risks": True, "upgrade_guidance": True \
                    , "minimum_severity": "medium", "available-during-analysis": True }
                response = requests.put(args.url + "/api/tool-connector-config/values/" + str(collector_id), headers=getHeader(), json=codedx_data)
                if response.status_code == 200:
                    logging.info("Project: " + project_name + " BD Collector added!")
                else:
                    logging.error(response.content)
                    logging.error("Project: " + project_name + " BD Collector adding failed!")

def addPolarisCollector(project_id, project_name, branch_name):
    global args
    if project_id:
        codedx_data = { "tool": "Polaris", "name": "Polaris Connector" }
        response = requests.post(args.url + "/api/tool-connector-config/entries/" + str(project_id), headers=getHeader(), json=codedx_data)
        if response.status_code == 201:
            collector_id = response.json()['id']
            if collector_id:
                # Lets get polaris project and branch ids
                polaris_projectId, polaris_streamId = Polaris(args.collector_url, args.collector_apikey).getProjectandBranchIds(project_name, branch_name)
                if polaris_projectId:
                    codedx_data = {
                        "server_url": args.collector_url, 
                        "api_token": args.collector_apikey, 
                        "connector_mode": "project", 
                        "application": "", 
                        "project": polaris_projectId, 
                        "branch": f'{polaris_streamId if polaris_streamId else "cdx_default_branch"}',
                        "available-during-analysis": True
                    }
                    response = requests.put(args.url + "/api/tool-connector-config/values/" + str(collector_id), headers=getHeader(), json=codedx_data)
                    if response.status_code == 200:
                        logging.info("Project: " + project_name + " Polaris Collector added!")
                    else:
                        logging.error(response.content)
                        logging.error("Project: " + project_name + " Polaris Collector adding failed!")

def getBDProjectIDByName(project_name):
    hub = HubInstance(args.collector_url, api_token=args.collector_apikey, insecure=False)
    project = hub.get_project_by_name(project_name)
    if project:
        logging.debug(project['_meta']['href'].split("/")[-1])
        return project['_meta']['href'].split("/")[-1]

#
# Only Coverity, Black Duck Hub and Polaris types are supported
#
def addCollector(project_id, collector_types):
    if collector_types and not collector_types == 'ALL':
        for collector_type in collector_types:
            if collector_type.lower() == 'coverity':
                addCoverityCollector(project_id, args.project, args.branch)
            elif collector_type.lower() == 'polaris':
                addPolarisCollector(project_id, args.project, args.branch)
            elif collector_type.lower() == 'black duck hub':
                addBlackDuckCollector(project_id, args.project, args.branch)
            else:
                logging.info(f"Creation of the collector type {collector_type} is not supported. Only supporter types are: Coverity, Black Duck Hub and Polaris")
        
def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

if __name__ == '__main__':
    # Parse the argument
    parser = argparse.ArgumentParser(
        description="CVMS collector triggerer"
    )
    parser.add_argument("--url", help="CVMS URL", required=True)
    parser.add_argument("--apikey", help="Api-key for CVMS", required=True)
    parser.add_argument("--project", help="Repository name", required=True)
    parser.add_argument("--branch", help="Repository name", required=False)
    parser.add_argument("--collector_type", help="Collector type (options: ASoC,AppScan Enterprise,Aqua CSP,Black Duck Binary Analysis,Black Duck Hub,Burp Enterprise,Checkmarx, \
            Checkmarx IAST,CodeSonar,Contrast,Coverity,Data Theorem Mobile,DefenseCode ThunderScan,Dependency-Track,Fortify Software Security Center,GitHub Advanced Security, \
            JFrog Xray,Netsparker Enterprise,NowSecure,Polaris,Prisma Cloud (RedLock),Prisma Cloud Compute (Twistlock),Qualys VM,Qualys WAS,\
            Rapid7 InsightAppSec,SD Elements,Seeker,Snyk,SonarQube,Sonatype Nexus,Synopsys Managed Services Platform,Tenable.io,Tenable.io Web App Scanning, \
            Tenable.sc,Tinfoil API,Tinfoil Web,Trustwave App Scanner,Veracode,WhiteHat Sentinel,WhiteSource, ALL). Comma separated list if you want to \
            run more than one type on the same time.", required=True)
    parser.add_argument("--collector_name", help="Collector name, if there are multiple collectors with same collector type by using the name of the collector, you can run only the wanted one.", default="", required=False)
    parser.add_argument("--wait_analysis", help="Set this True, if you need to wait until the data import is done", default=False, required=False, type=str2bool)
    parser.add_argument("--filename", help="XML filename with full path", default="")
    parser.add_argument("--tag", help="Tag which is used to find the project from CVMS, default=\"integration_name\"", default="integration_name", required=False)
    parser.add_argument("--create_if_not_exists", help="Set this True, if you need to create the project.", default=False, required=False, type=str2bool)
    parser.add_argument("--collector_username", help="Username for collector integration", required=False)
    parser.add_argument("--collector_password", help="Password for collector integration", required=False)
    parser.add_argument("--collector_url", help="Url for collector integration", required=False)
    parser.add_argument("--collector_apikey", help="Url for collector integration", required=False)
    parser.add_argument('--log_level', help="Will print more info... default=INFO", default="DEBUG")
    args = parser.parse_args()
    # Printing out the version number
    if args.log_level == "9": log_level = "DEBUG"
    elif args.log_level == "0": log_level = "INFO"
    else: log_level = args.log_level
    logging.basicConfig(level=log_level.upper())
    logging.info("CVMS utility version: " + __versionro__)
    # Printing out all parameters if log level is DEBUG
    if (logging.getLogger().isEnabledFor(logging.DEBUG)):
        logging.debug("All settings used:")
        for k, v in sorted(vars(args).items()):
            if (k != "apikey" and k != 'collector_password' and k != 'collector_username'):
                logging.debug("{0}: {1}".format(k, v))
    try:
        project_id = getProjectIdByName()
        if not project_id:
            if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                logging.debug("Project was not found with project name -> trying to find project with tag \"integration_name\"..")
            #Testing if the tag "integration_name" in metadata has the given project name
            project_id = getProjectIdByTags(args.project)
        if not project_id and args.create_if_not_exists:
            logging.debug(f'Project with name {args.project} was not found and create_if_not_exists=True -> will create the project.')
            project_id = createProject(args.project)
        if project_id:
            if not args.filename:
                collectors = getProjectCollectorIDs(project_id, args.collector_type.split(','))
                if not collectors or len(collectors) == 0 and args.create_if_not_exists:
                    # There was no requested collector -> create one
                    addCollector(project_id, args.collector_type.split(','))
                    collectors = getProjectCollectorIDs(project_id, args.collector_type.split(','))
                if collectors and len(collectors) > 0:
                    for collector in collectors:
                        job_id = triggerCollectors(project_id, collector)
                        if job_id:
                            if args.wait_analysis == True:
                                polling.poll(lambda: checkStatus(job_id), check_success=checkSuccess, step=4, timeout=1800)
                            logging.info(f"CVMS collector {collector['name']} triggering done!")
                        else:
                            logging.debug("No job_id -> something has went wrong!")
                else:
                    logging.info("There was no collectors configured for project: " + args.project)
            else:
                job_id = sendFileForAnalysis(project_id, args.filename)
                if job_id and args.wait_analysis == True:
                    polling.poll(lambda: checkStatus(job_id), check_success=checkSuccess, step=4, timeout=1800)
                    logging.info("File: " + args.filename + " has been analyzed!")
                else:
                    if not job_id:
                        logging.debug("No job_id -> something has went wrong!")
        else:
            logging.info("Project with name: " + args.project + " was not found!")
        logging.info("---done!")
    except Exception as e:
        logging.error(e)

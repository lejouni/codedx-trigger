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

__author__ = "Jouni Lehto"
__versionro__ = "0.1"

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
    codedx_filter = {"filter": {"name": args.repository}}
    response = requests.post(f'{args.url}/codedx/api/projects/query', headers=getHeader(), json=codedx_filter)
    if response.status_code == 200:
        for project in response.json():
            if project['name'] == args.repository:
                if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                    logging.debug(project)
                return project['id']
        # If project list is is empty or not contain exact the same project name than given as repository
        logging.error("Project: " + args.repository + " not found!")
    else:
        logging.error(response)

def getProjectIdByTags(tags):
    codedx_filter = {"filter": { "metadata": { args.tag: tags}}}
    response = requests.post(f'{args.url}/codedx/api/projects/query', headers=getHeader(), json=codedx_filter)
    if response.status_code == 200:
        for project in response.json():
            for metadata in project['metadata']:
                if metadata['name'] == args.tag and metadata['value'].strip() == args.repository:
                    if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                        logging.debug(project)
                    return project['id']
        # If project list is is empty or not contain exact the same project name than given as repository
        logging.error("Project: " + args.repository + " not found!")
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
            elif data["tool"] in collector_types:
                if args.collector_name:
                    if args.collector_name.lower() == data["name"].lower():
                        collectorIds.append({"name": data["name"], "id": data["id"]})
                        return collectorIds
                else:
                    collectorIds.append({"name": data["name"], "id": data["id"]})
        return collectorIds

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

def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

if __name__ == '__main__':
    # Parse the argument
    parser = argparse.ArgumentParser(
        description="CVMS collector triggerer"
    )
    parser.add_argument("--url", help="CVMS URL", required=True)
    parser.add_argument("--apikey", help="Api-key for CVMS", required=True)
    parser.add_argument("--repository", help="Repository name", required=True)
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
    parser.add_argument("--create_project_if_not_exists", help="Set this True, if you need to create the project.", default=False, required=False, type=str2bool)
    parser.add_argument("--log_level", help="Log level? (INFO or DEBUG)", default="INFO")
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
            if (k != "apikey"):
                logging.debug("{0}: {1}".format(k, v))
    try:
        project_id = getProjectIdByName()
        if not project_id:
            if (logging.getLogger().isEnabledFor(logging.DEBUG)):
                logging.debug("Project was not found with project name -> trying to find project with tag \"integration_name\"..")
            #Testing if the tag "integration_name" in metadata has the given project name
            project_id = getProjectIdByTags(args.repository)
        if not project_id and args.create_project_if_not_exists:
            logging.debug(f'Project with name {args.repository} was not found and create_project_if_not_exists=True -> will create the project.')
            project_id = createProject(args.repository)
        if project_id:
            if not args.filename:
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
                    logging.info("There was no collectors configured for project: " + args.repository)
            else:
                job_id = sendFileForAnalysis(project_id, args.filename)
                if job_id and args.wait_analysis == True:
                    polling.poll(lambda: checkStatus(job_id), check_success=checkSuccess, step=4, timeout=1800)
                    logging.info("File: " + args.filename + " has been analyzed!")
                else:
                    if not job_id:
                        logging.debug("No job_id -> something has went wrong!")
        else:
            logging.info("Project with name: " + args.repository + " was not found!")
        logging.info("---done!")
    except Exception as e:
        logging.error(e)

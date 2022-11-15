# codedx-trigger
With this Github action you can trigger any native Code Dx collector you have configured in your Code Dx project. You can also send result file into Code Dx for vulnerability management. If you have configured multiple same type of collectors in your Code Dx project and you don't want to trigger them all, you can specify the collector which you want to trigger by giving the collector name with input parameter *collector_name*.

You can use this action also to create project into Code Dx if it doesn't exists yet by giving the input parameter *create_if_not_exists=true*. If given collector doesn't exits in your project configuration, it will be added if *create_if_not_exists=true*. The collector creation is supported only for Coverity, Black Duck Hub and Polaris -collector types.

Supported collector types for triggering: "ASoC","AppScan Enterprise","Aqua CSP","Black Duck Binary Analysis","Black Duck Hub","Burp Enterprise","Checkmarx","Checkmarx IAST","CodeSonar","Contrast","Coverity","Data Theorem Mobile","DefenseCode ThunderScan","Dependency-Track","Fortify Software Security Center","GitHub Advanced Security","JFrog Xray","Netsparker Enterprise","NowSecure","Polaris","Prisma Cloud (RedLock)","Prisma Cloud Compute (Twistlock)","Qualys VM","Qualys WAS","Rapid7 InsightAppSec","SD Elements","Seeker","Snyk","SonarQube","Sonatype Nexus","Synopsys Managed Services Platform","Tenable.io","Tenable.io Web App Scanning","Tenable.sc","Tinfoil API","Tinfoil Web","Trustwave App Scanner","Veracode","WhiteHat Sentinel","WhiteSource". Give comma separated list if you want to run more than one type on the same time. If you want to trigger all collectors which you have on your project and which are supported, you can do that by giving "ALL" as a collector type.

## Available Options
| Option name | Description | Default value | Required |
|----------|----------|---------|----------|
| log_level | Set the logging level | INFO | false |
| project | Project name in Code Dx | ${{github.repository}} | false |
| branch | Project branch name | ${{github.ref_name}} | false |
| tag | Project tag which is used to find the project from Code Dx. | - | false |
| collector_type_to_trigger | Collector type to trigger. Options are "ASoC","AppScan Enterprise","Aqua CSP","Black Duck Binary Analysis","Black Duck Hub","Burp Enterprise","Checkmarx","Checkmarx IAST","CodeSonar","Contrast","Coverity","Data Theorem Mobile","DefenseCode ThunderScan","Dependency-Track","Fortify Software Security Center","GitHub Advanced Security","JFrog Xray","Netsparker Enterprise","NowSecure","Polaris","Prisma Cloud (RedLock)","Prisma Cloud Compute (Twistlock)","Qualys VM","Qualys WAS","Rapid7 InsightAppSec","SD Elements","Seeker","Snyk","SonarQube","Sonatype Nexus","Synopsys Managed Services Platform","Tenable.io","Tenable.io Web App Scanning","Tenable.sc","Tinfoil API","Tinfoil Web","Trustwave App Scanner","Veracode","WhiteHat Sentinel","WhiteSource" and "ALL" | - | true |
| collector_name | Name of the collector. This can be used to separate which collector to trigger, if there are multiple same type of collectors in the project. | - | false |
| input_filename | File name which to send into Code Dx | - | false |
| artifact_name | Artifact name where report file can be downloaded | - | If input_filename is given then true, else false |
| wait_analysis | Wait the analysis is ready. | false | false |
| create_if_not_exists | Create project into Code Dx, if its not exists yet. | false | false |
| codedx_access_token | Code Dx Api access token. | - | true |
| codedx_url | Code Dx server url. | - | true |
| collector_url | Url where collector is integrated with | - | false |
| collector_username | Username for collector which is integrated (Coverity) | - | false |
| collector_password | password for collector which is integrated (Coverity) | - | false |
| collector_apikey | Api key for collector integration (Black Duck Hub and Polaris) | - | false |

## Usage examples
Trigger Coverity Connect -collector
```yaml
    - name: Trigger Code Dx
      uses: lejouni/codedx-trigger@v0.1.13
      with:
        project: test-project
        collector_type_to_trigger: Coverity
        wait_analysis: false
        codedx_access_token: ${{secrets.CODEDX_ACCESS_TOKEN}}
        codedx_url: ${{secrets.CODEDX_SERVER_URL}}
```
Trigger Black Duck Hub -collector
```yaml
    - name: Trigger Code Dx
      uses: lejouni/codedx-trigger@v0.1.13
      with:
        project: test-project
        collector_type_to_trigger: Black Duck Hub
        wait_analysis: false
        codedx_access_token: ${{secrets.CODEDX_ACCESS_TOKEN}}
        codedx_url: ${{secrets.CODEDX_SERVER_URL}}
```
Trigger All -collectors what project has.
```yaml
    - name: Trigger Code Dx
      uses: lejouni/codedx-trigger@v0.1.13
      with:
        project: test-project
        collector_type_to_trigger: ALL
        wait_analysis: false
        codedx_access_token: ${{secrets.CODEDX_ACCESS_TOKEN}}
        codedx_url: ${{secrets.CODEDX_SERVER_URL}}
```
Trigger Coverity Connect -collector and create project and collector if they don't exists yet.
```yaml
    - name: Trigger Code Dx
      uses: lejouni/codedx-trigger@v0.1.13
      with:
        project: test-project
        branch: test-project-main
        collector_type_to_trigger: Coverity
        create_if_not_exists: true
        wait_analysis: false
        log_level: DEBUG
        codedx_access_token: ${{secrets.CODEDX_ACCESS_TOKEN}}
        codedx_url: ${{secrets.CODEDX_SERVER_URL}}
        collector_url: ${{secrets.COVERITY_SERVER_URL}}
        collector_username: ${{secrets.COVERITY_USERNAME}}
        collector_password: ${{secrets.COVERITY_ACCESS_TOKEN}}
```
Send result file into Code Dx for vulnerability management. The file, which you want to send Code Dx must be first saved as an artifact, then you need to give that artifact name and filename to this action as a parameter.
```yaml
    - name: Trigger Code Dx
      uses: lejouni/codedx-trigger@v0.1.13
      with:
        artifact_name: checkov-scan-results
        input_filename: results.sarif
        create_project_if_not_exists: true
        collector_type_to_trigger: Checkov
        wait_analysis: true
        codedx_access_token: ${{secrets.CODEDX_ACCESS_TOKEN}}
        codedx_url: ${{secrets.CODEDX_SERVER_URL}}
```

Example to run Coverity analysis and after analysis trigger the Code Dx to collect the latest results from Coverity Connect. In this example, we are only interested to collect **full** analysis results into Code Dx and results from incremental analysis are available only locally.
```yaml
name: Java CI with Maven and Coverity

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3 # This will checkout the source codes from repository
    - name: Set up JDK 1.11 # This will add Java into the runners PATH
      uses: actions/setup-java@v3.6.0
      with:
        java-version: '11'
        distribution: 'temurin'
        cache: 'maven'
    - name: Set up Coverity # This will add Coverity Analysis tools into runner PATH
      uses: lejouni/setup-coverity-analysis@v2.8.20
      with:
        cov_version: cov-analysis-linux64-2022.6.1
        cov_url: ${{secrets.COVERITY_SERVER_URL}} #Coverity Connect server URL
        cov_license: ${{github.workspace}}/scripts/license.dat
        cov_username: ${{secrets.COVERITY_USERNAME}} #Coverity Connect username
        cov_password: ${{secrets.COVERITY_ACCESS_TOKEN}} #Coverity Connect password
        cov_output_format: sarif #Optional, but if given the options are html, json and sarif
        cov_output: ${{github.workspace}}/coverity_results.sarif.json
        project: test-project #Project name can be given, but if not, then repository name is used as a project name
        stream: test-project-main #Stream can be give as well, but if not, then repository name-branch name is used.
        create_if_not_exists: true # will create project and stream if they don't exists yet
        cache: coverity # Optional, but if given the options are coverity, idir and all
    - if: ${{github.event_name == 'pull_request'}}
      name: Build with Maven and Full Analyze with Coverity # This will run the full Coverity Analsysis
      uses: lejouni/coverity-build-analysis@v4.3.5
      with:
        build_command: mvn -B package --file pom.xml
    - if: ${{github.event_name == 'push'}}
      name: Build with Maven and Incremental Analyze with Coverity # This will run the incremental Coverity Analsysis
      uses: lejouni/coverity-build-analysis@v4.3.5
      with:
        build_command: mvn -B package --file pom.xml
        cov_analysis_mode: incremental # Optional, but options are full (default) or incremental
        github_access_token: ${{secrets.ACCESS_TOKEN_GITHUB}} # this is required in incremental mode, used to get changed files via Github API
    - if: ${{github.event_name == 'pull_request'}}
      name: Trigger Code Dx
      uses: lejouni/codedx-trigger@v0.1.13
      with:
        project: ${{env.project}}
        branch: ${{env.stream}}
        collector_type_to_trigger: Coverity
        create_if_not_exists: true
        wait_analysis: false
        log_level: DEBUG
        codedx_access_token: ${{secrets.CODEDX_ACCESS_TOKEN}}
        codedx_url: ${{secrets.CODEDX_SERVER_URL}}
        collector_url: ${{secrets.COVERITY_SERVER_URL}}
        collector_username: ${{secrets.COVERITY_USERNAME}}
        collector_password: ${{secrets.COVERITY_ACCESS_TOKEN}}
    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        # Path to SARIF file
        sarif_file: ${{github.workspace}}/coverity_results.sarif.json
      continue-on-error: true
    - name: Archive scanning results
      uses: actions/upload-artifact@v3
      with:
        name: coverity-scan-results
        path: ${{github.workspace}}/coverity_results.sarif.json
      continue-on-error: true
```
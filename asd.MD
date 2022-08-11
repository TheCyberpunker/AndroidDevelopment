# Pentesting Cloud - Azure - Summary

- \[\[#Get Secrets Values - Azure\|Get Secrets Values - Azure\]\]
- \[\[#Microsoft Resources in Azure Active Directory\|Microsoft Resources in Azure Active Directory\]\]
- \[\[#Get the Azure AD info - Azure Key Vault\|Get the Azure AD info - Azure Key Vault\]\]
  - \[\[#Get the Azure AD info - Azure Key Vault#Get a JWT Token for Azure Key Vault with Postman - Example.\|Get a JWT Token for Azure Key Vault with Postman - Example.\]\]
  - \[\[#Get the Azure AD info - Azure Key Vault#Get a JWT token for Azure Key Vault with BurpSuite - Example.\|Get a JWT token for Azure Key Vault with BurpSuite - Example.\]\]
  - \[\[#Get the Azure AD info - Azure Key Vault#Get a JWT token for Azure Key Vault with Curl - Example\|Get a JWT token for Azure Key Vault with Curl - Example\]\]
- \[\[#Access Azure Key Vault Secrets with a token JWT - Postman Example\|Access Azure Key Vault Secrets with a token JWT - Postman Example\]\]
- \[\[#Access Azure Key Vault Secrets with a token JWT - BurpSuite Example\|Access Azure Key Vault Secrets with a token JWT - BurpSuite Example\]\]
- \[\[#Access Azure Key Vault Secrets with the token JWT with CURL - Example\|Access Azure Key Vault Secrets with the token JWT with CURL - Example\]\]
- \[\[#Get the Azure AD info - Microsoft Graph\|Get the Azure AD info - Microsoft Graph\]\]
  - \[\[#Get the Azure AD info - Microsoft Graph#Get a JWT Token for Microsoft Graph with Burpsuite - Example.\|Get a JWT Token for Microsoft Graph with Burpsuite - Example.\]\]
  - \[\[#Get the Azure AD info - Microsoft Graph#Get a JWT Token for Microsoft Graph with Curl - Example.\|Get a JWT Token for Microsoft Graph with Curl - Example.\]\]
- \[\[#Access Microsoft Graph with a token JWT - Burpsuite Example\|Access Microsoft Graph with a token JWT - Burpsuite Example\]\]
- \[\[#Access Microsoft Graph with a token JWT - Curl Example\|Access Microsoft Graph with a token JWT - Curl Example\]\]
- \[\[#Get the Azure AD info - Azure Blob Storage\|Get the Azure AD info - Azure Blob Storage\]\]
  - \[\[#Get the Azure AD info - Azure Blob Storage#Get a Connection String for Azure Blob with Python - Example.\|Get a Connection String for Azure Blob with Python - Example.\]\]
- \[\[#Access Azure Blob Storage - Storage Explorer\|Access Azure Blob Storage - Storage Explorer\]\]
  - \[\[#Access Azure Blob Storage - Storage Explorer#Install Storage Explorer\|Install Storage Explorer\]\]
- \[\[#Access Azure Blob Storage with a Connection String - Storage Explorer Example\|Access Azure Blob Storage with a Connection String - Storage Explorer Example\]\]
- \[\[#Other Curl Commands\|Other Curl Commands\]\]
- \[\[#Pentesting Cloud - Azure - Resources\|Pentesting Cloud - Azure - Resources\]\]
- \[\[#Pentesting Cloud - Azure - Tools\|Pentesting Cloud - Azure - Tools\]\]
- \[\[#Pentesting - General\|Pentesting - General\]\]

## Get Secrets Values - Azure

I am assuming that you already have a Key Vault service instance in Azure with some Secrets.

## Microsoft Resources in Azure Active Directory

Common Microsoft Resources in Azure Active Directory

- [shawntabrizi.com/aad/common-microsoft-resources-azure-active-directory](https://www.shawntabrizi.com/aad/common-microsoft-resources-azure-active-directory/) - Common Microsoft Resources Azure Active Directory

| Resource Name                        | Resource URI                         | Application ID                       |
|--------------------------------------|--------------------------------------|--------------------------------------|
| AAD Graph API                        | https://graph.windows.net/           | 00000002-0000-0000-c000-000000000000 |
| Office 365 Exchange Online           | https://outlook-sdf.office.com/      | 00000002-0000-0ff1-ce00-000000000000 |
| Microsoft Graph                      | https://graph.microsoft.com          | 00000003-0000-0000-c000-000000000000 |
| Skype for Business Online            | https://api.skypeforbusiness.com/    | 00000004-0000-0ff1-ce00-000000000000 |
| Office 365 Yammer                    | https://api.yammer.com/              | 00000005-0000-0ff1-ce00-000000000000 |
| OneNote                              | https://onenote.com/                 | 2d4d3d8e-2be3-4bef-9f87-7875a61c29de |
| Windows Azure Service Management API | https://management.core.windows.net/ | 797f4846-ba00-4fd7-ba43-dac1f8f63013 |
| Office 365 Management APIs           | https://manage.office.com            | c5393580-f805-4401-95e8-94b7a6ef2fc2 |
| Microsoft Teams Services             | https://api.spaces.skype.com/        | cc15fd57-2c6c-4117-a88c-83b1d56b4bbe |
| Azure Key Vault                      | https://vault.azure.net              | cfa8b339-82a2-471a-a3c9-0fc0be7a4093 |

## Get the Azure AD info - Azure Key Vault

**Example**s

``` shell
# GET THIS DATA.

TenantId: 
client_id : 
client_secret :
keyvaultname :
secretname :
```

``` yaml
{
    "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft": "Warning",
        "Microsoft.Hosting.Lifetime": "Information"
      }
    },

    "AllowedHosts": "*",
    "AppConfiguration": {
        "TenantId": "127ef231-REDA-CTED-3c621-REDACTEDdb2f",
        "client_secret": "aFG4~DA-rEd4c1edgLFlGJREDACTE~D61.",
        "client_id": "2a193183-REDA-CTED-3c65-18434aecdfg2",
        "KeyVaultName": "Keyvault-REDACTED",
        "SecretName": "NameRedacted"
    }
}
```

\[\[Pasted image 20220811040635.png\]\]

### Get a JWT Token for Azure Key Vault with Postman - Example.

\[\[Pasted image 20220616101900.png\]\]

- [c-sharpcorner.com/article/how-to-access-azure-key-vault-secrets-through-rest-api-using-postman](https://www.c-sharpcorner.com/article/how-to-access-azure-key-vault-secrets-through-rest-api-using-postman/) - Read the full post.

Here, request url for access token can be copied from your registered app in Azure AD. Otherwise you can copy below url and replace {tenantID} value with Directory ID of your registered app in Azure AD.

URL : POST *https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token*

These are the four keys that you have to mention here in request body while calling this endpoint.

1.  grant_type : client_credentials
2.  client_id : Copy Application ID from your registered app in Azure AD. Blue circle for below screenshot for your reference.
3.  client_secret : This will be Client secret value of your registered app in Azure AD.
4.  scope : https://vault.azure.net/.default.

### Get a JWT token for Azure Key Vault with BurpSuite - Example.

**Request Example**

``` shell
# host 
https://login.microsoftonline.com/<TENANT>/oauth2/v2.0/token
# host

POST /<TENANT ID>/oauth2/v2.0/token HTTP/1.1
User-Agent: PostmanRuntime/7.29.0
Accept: */*
Postman-Token: a22b62f6-82bc-4f9e-8e6f-0235e123be3e
Host: login.microsoftonline.com
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 175

grant_type=%20client_credentials&client_id=<CLIENT ID>&client_secret=<CLIENT SECRET>&scope=https%3A%2F%2Fvault.azure.net%2F.default
# scope: https://vault.azure.net/.default
```

**Response Example**

``` yaml
{
    "token_type":"Bearer",
    "expires_in":"3599",
    "ext_expires_in":"3599",
    "access_token":"eyJ0eXAi.EXAMPLE."
}
```

\[\[Pasted image 20220811035324.png\]\]

### Get a JWT token for Azure Key Vault with Curl - Example

**Note**: To send the request from curl to Burpsuite use the next flags on the curl command.

``` shell
-x 127.0.0.1:8080 -k
```

**Request access token**

``` shell
curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' https://login.microsoftonline.com/<TENANT-ID>/oauth2/v2.0/token -d 'client_id=<CLIENT-ID>' -d 'client_secret=<CLIENTS-SECRET>' -d 'scope=https%3A%2F%2Fvault.azure.net%2F.default' -d 'grant_type=client_credentials'
```

\[\[Pasted image 20220811042928.png\]\]

## Access Azure Key Vault Secrets with a token JWT - Postman Example

**Azure AD info**

``` yaml
{
    "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft": "Warning",
        "Microsoft.Hosting.Lifetime": "Information"
      }
    },

    "AllowedHosts": "*",
    "AppConfiguration": {
        "TenantId": "127ef231-REDA-CTED-3c621-REDACTEDdb2f",
        "client_secret": "aFG4~DA-rEd4c1edgLFlGJREDACTE~D61.",
        "client_id": "2a193183-REDA-CTED-3c65-18434aecdfg2",
        "KeyVaultName": "Keyvault-REDACTED",
        "SecretName": "NameRedacted"
    }
}
```

\[\[Pasted image 20220811040635.png\]\]

``` shell
URL : GET _https://<KeyVaultName>.vault.azure.net/secrets/<SecretName>?api-version=2016-10-01_
```

\[\[Pasted image 20220616105614.png\]\]

## Access Azure Key Vault Secrets with a token JWT - BurpSuite Example

**Check the Azure AD info for this example**

``` yaml
{
    "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft": "Warning",
        "Microsoft.Hosting.Lifetime": "Information"
      }
    },

    "AllowedHosts": "*",
    "AppConfiguration": {
        "TenantId": "127ef231-REDA-CTED-3c621-REDACTEDdb2f",
        "client_secret": "aFG4~DA-rEd4c1edgLFlGJREDACTE~D61.",
        "client_id": "2a193183-REDA-CTED-3c65-18434aecdfg2",
        "KeyVaultName": "Keyvault-REDACTED",
        "SecretName": "NameRedacted"
    }
}
```

``` shell
URL : GET _https://<KeyVaultName>.vault.azure.net/secrets/<SecretName>?api-version=2016-10-01_
```

\[\[Pasted image 20220811043705.png\]\]

## Access Azure Key Vault Secrets with the token JWT with CURL - Example

**Note**: To send the request from curl to Burpsuite use the next flags on the curl command.

``` shell
-x 127.0.0.1:8080 -k
```

**Check the Azure AD info for this example**

``` yaml
{
    "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft": "Warning",
        "Microsoft.Hosting.Lifetime": "Information"
      }
    },

    "AllowedHosts": "*",
    "AppConfiguration": {
        "TenantId": "127ef231-REDA-CTED-3c621-REDACTEDdb2f",
        "client_secret": "aFG4~DA-rEd4c1edgLFlGJREDACTE~D61.",
        "client_id": "2a193183-REDA-CTED-3c65-18434aecdfg2",
        "KeyVaultName": "Keyvault-REDACTED",
        "SecretName": "NameRedacted"
    }
}
```

**Request Curl**

``` shell
curl -i -s -k -X $'GET' -H $'Host: <KeyVaultName>.vault.azure.net' -H $'Authorization: Bearer eysadad<TOKEN>d....' $'https://<KeyVaultName>.vault.azure.net/secrets/<SecretName>?api-version=2016-10-01'
```

**Response Curl - Example**

``` shell
{"value":"Server=<KeyVaultName>.database.windows.net,1433;Database=<KeyVaultName>;Authentication=Active Directory Default;","id":"https://<KeyVaultName>.vault.azure.net/secrets/<SecretName>/282REDACTED448813a5a4a74s9dvd","attributes":{"enabled":true,"created":1649473595,"updated":1649473595,"recoveryLevel":"Recoverable+Purgeable"},"tags":{}}
```

\[\[Pasted image 20220811045530.png\]\]

## Get the Azure AD info - Microsoft Graph

**Example**s

``` shell
# GET THIS DATA.

TenantId: 
client_id : 
client_secret :
keyvaultname :
secretname :
```

``` yaml
{
    "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft": "Warning",
        "Microsoft.Hosting.Lifetime": "Information"
      }
    },

    "AllowedHosts": "*",
    "AppConfiguration": {
        "TenantId": "127ef231-REDA-CTED-3c621-REDACTEDdb2f",
        "client_secret": "aFG4~DA-rEd4c1edgLFlGJREDACTE~D61.",
        "client_id": "2a193183-REDA-CTED-3c65-18434aecdfg2",
        "KeyVaultName": "Keyvault-REDACTED",
        "SecretName": "NameRedacted"
    }
}
```

\[\[Pasted image 20220811040635.png\]\]

### Get a JWT Token for Microsoft Graph with Burpsuite - Example.

``` shell
POST /<TENANTID>/oauth2/v2.0/token HTTP/1.1
User-Agent: PostmanRuntime/7.29.0
Accept: */*
Postman-Token: a22b62f6-82bc-4f9e-8e6f-0235e123be3e
Host: login.microsoftonline.com
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 175
Cookie: fpc=AmKlTUvVrQ9FoPo-DnuEJ3c

grant_type=%20client_credentials&client_id=<CLIENT ID>&client_secret=<CLIENT SECRET>&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default

# scope https://graph.microsoft.com
```

\[\[2022-08-11_05-25.png\]\]

### Get a JWT Token for Microsoft Graph with Curl - Example.

**Note**: To send the request from curl to Burpsuite use the next flags on the curl command.

``` shell
-x 127.0.0.1:8080 -k
```

**Request access token**

``` shell
curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' https://login.microsoftonline.com/<TENANT-ID>/oauth2/v2.0/token -d 'client_id=<CLIENT-ID>' -d 'client_secret=<CLIENTS-SECRET>' -d 'scope=https%3A%2F%2Fgraph.microsoft.com%2F.default' -d 'grant_type=client_credentials'

# scope https://graph.microsoft.com
```

\[\[Pasted image 20220811053606.png\]\]

## Access Microsoft Graph with a token JWT - Burpsuite Example

**Note**: You need only a token JWT

``` shell
URL : GET https://graph.microsoft.com/v1.0/
```

**Note**: You can try with different methods:

``` shell
https://graph.microsoft.com/v1.0/
https://graph.microsoft.com/v1.0/me
https://graph.microsoft.com/v1.0/users
https://graph.microsoft.com/v1.0/OTHERMETHODS...
```

**Example: Access data and methods**

**Request**

``` shell
GET /v1.0/ HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJ0eXAasd.... TOKEN
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,es;q=0.8
Connection: close
```

**Response**\*

``` shell
{
"@odata.context":"https://graph.microsoft.com/v1.0/$metadata",
"value":[
 {
    "name":"invitations",
    "kind":"EntitySet",
    "url":"invitations"},
 {
    "name":"users",
    "kind":"EntitySet",
    "url":"users"
}
............ #more
```

\[\[Pasted image 20220811054812.png\]\]

``` shell
URL : GET https://graph.microsoft.com/v1.0/users
```

**Example: Access users method**

**Request**

``` shell
GET /v1.0/users HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJ0eXAasd.... TOKEN
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,es;q=0.8
Connection: close
```

**Response**\*

``` shell
{
"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users",
"@odata.nextLink":"https://graph.microsoft.com/v1.0/users?$skiptoken=REDACTED",
"value":[
 {
 ## ALL SENSITIVE DATA LIKE phones, users, business information
    "mail":"mail",
    "kind":"EntitySet",
    "name":"name"},
 {
    "name":"users",
    "kind":"EntitySet",
    "url":"users"
}
............ #more
```

\[\[Pasted image 20220811055625.png\]\]

## Access Microsoft Graph with a token JWT - Curl Example

**Note**: To send the request from curl to Burpsuite use the next flags on the curl command.

``` shell
-x 127.0.0.1:8080 -k
```

**Request Curl**

``` shell
curl -X GET -H "Authorization: Bearer eyJ0eXAiOiJKV1......TOKEN>g" 'https://graph.microsoft.com/v1.0/'
```

**Response Curl - Example**

``` shell
{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata","value":[{"name":"invitations","kind":"EntitySet","url":"invitations"},{"name":"users","kind":"EntitySet","url":"users"},{"name":"applicationTemplates","kind":"EntitySet","url":"applicationTemplates"},{"name":"authenticationMethodConfigurations","kind":"EntitySet","url":"authenticationMethodConfigurations"},{"name":"identityProviders","kind":"EntitySet","url":"identityProviders"},{"name":"applications","kind":"EntitySet","url":"applications"},{"name":"certificateBasedAuthConfiguration","kind":"EntitySet","url":"certificateBasedAuthConfiguration"},{"name":"contacts","kind":"EntitySet","url":"contacts"}........ #more
```

\[\[Pasted image 20220811060946.png\]\]

## Get the Azure AD info - Azure Blob Storage

**Example**s

``` shell
# GET THIS DATA.

TenantId: 
client_id : 
client_secret :
keyvaultname :
secretname :
```

``` yaml
{
    "Logging": {
        "LogLevel": {
        "Default": "Information",
        "Microsoft": "Warning",
        "Microsoft.Hosting.Lifetime": "Information"
      }
    },

    "AllowedHosts": "*",
    "AppConfiguration": {
        "TenantId": "127ef231-REDA-CTED-3c621-REDACTEDdb2f",
        "client_secret": "aFG4~DA-rEd4c1edgLFlGJREDACTE~D61.",
        "client_id": "2a193183-REDA-CTED-3c65-18434aecdfg2",
        "KeyVaultName": "Keyvault-REDACTED",
        "SecretName": "NameRedacted"
    }
}
```

\[\[Pasted image 20220811070747.png\]\]

### Get a Connection String for Azure Blob with Python - Example.

``` python
# Script by Retr02332
from http import client
from azure.identity import ClientSecretCredential
from azure.identity import UsernamePasswordCredential
from azure.keyvault.secrets import SecretClient

VAULT = "<VAULTNAME>" # replace <VAULT NAME>
VAULT_URL = f"https://{VAULT}.vault.azure.net/" # not change
CLIENT_ID = "82732415-reDA-CTED-3222-25d3SFc6Rfd4" # Replace <CLIENT ID>
SECRET_ID = "135p=REDACT.E:DASFjP8ny.MASDWSDnu_lt" # Replace <SECRET ID>
TENANT_ID = "<TENANTID>" # Replace <CLIENT TENTANT ID>

credential = ClientSecretCredential(
    client_id=CLIENT_ID,
    client_secret=SECRET_ID,
    tenant_id=TENANT_ID
)

client = SecretClient(vault_url=VAULT_URL, credential=credential)

secret = client.get_secret("").value

print("\nSecret: " + secret)
```

\[\[Pasted image 20220811071544.png\]\]

**Example Connection String**

``` shell
DefaultEndpointsProtocol=https;AccountName=AZ-test-account;AccountKey=7123123REdacted.....===;EndpointSuffix=core.windows.net
```

## Access Azure Blob Storage - Storage Explorer

### Install Storage Explorer

Download and install Storage Explorer for the OS that you want.

- Download https://azure.microsoft.com/en-us/features/storage-explorer/

**Note:** Example Installation for linux

    cd Downloads
    tar -xvf storageexplorer.tar
    cd storageexplorer

- Install the .NET SDK or the .NET Runtime on Debian https://docs.microsoft.com/en-us/dotnet/core/install/linux-debian

``` shell
wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

sudo apt-get update
sudo apt-get install -y dotnet-sdk-6.0
```

- Run Storage Explorer

``` shell
cd storageexplorer
./StorageExplorer
```

## Access Azure Blob Storage with a Connection String - Storage Explorer Example

**Example Connection String**

``` shell
DefaultEndpointsProtocol=https;AccountName=AZ-test-account;AccountKey=7123123REdacted.....===;EndpointSuffix=core.windows.net
```

\[\[Pasted image 20220811073319.png\]\]

\[\[Pasted image 20220811073437.png\]\]

\[\[Pasted image 20220811073546.png\]\]

\[\[Pasted image 20220726042000.png\]\]

## Other Curl Commands

``` shell
curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' https://login.microsoftonline.com/<TENANT>/oauth2/token -d 'client_id=<CLIENT ID>' -d 'client_secret=<CLIENT SECRET>' -d 'grant_type=client_credentials'
```

``` shell
curl -X POST -d 'grant_type=client_credentials&client_id=<CLIENT-ID>&client_secret=<CLIENT-SECRET>&resource=https%3A%2F%2Fmanagement.azure.com%2F' https://login.microsoftonline.com/<TENANT-ID>/oauth2/token
```

``` shell
################################# call azure rest api
curl -X GET -H 'Authorization: Bearer eyJ0e,......A' -H 'Content-Type: application/json' https://management.azure.com/subscriptions/a<SUBSCRIPTION>f/providers/Microsoft.Web/sites?api-version=2016-08-01
```

## Pentesting Cloud - Azure - Resources

- [shawntabrizi.com/aad/common-microsoft-resources-azure-active-directory](https://www.shawntabrizi.com/aad/common-microsoft-resources-azure-active-directory/) - Common Microsoft Resources in Azure Active Directory.
- [mauridb.medium.com/calling-azure-rest-api-via-curl](https://mauridb.medium.com/calling-azure-rest-api-via-curl-eb10a06127) - Calling Azure REST API via curl.
- [github.com/rootsecdev/Azure-Red-Team](https://github.com/rootsecdev/Azure-Red-Team) - Azure read team methology and resources.
- [synacktiv.com/en/publications/azure-ad-introduction-for-red-teamers](https://www.synacktiv.com/en/publications/azure-ad-introduction-for-red-teamers.html) - Azure readteam guide.
- [microsoft.com/en-us/azure/databricks/dev-tools/api/latest/aad/app-aad-token](https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/aad/app-aad-token) - Get Azure AD tokens by using the Microsoft Authentication Library.
- [c-sharpcorner.com/article/how-to-access-azure-key-vault-secrets-through-rest-api-using-postman](https://www.c-sharpcorner.com/article/how-to-access-azure-key-vault-secrets-through-rest-api-using-postman/) - How To Access Azure Key Vault Secrets Through Rest API Using Postman.
- [github.com/swisskyrepo/PayloadsAllTheThings/Azure](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md) - Azure Active Directory pentesting
- [blog.zuehlke.cloud/2019/10/access-azure-blob-storage-with-rest-and-sas](https://blog.zuehlke.cloud/2019/10/access-azure-blob-storage-with-rest-and-sas/) - Access Azure Blob Storage with REST and SAS.
- [nishantrana.me/2020/12/15/read-secret-from-azure-key-vault-using-key-vault-rest-api-through-postman](https://nishantrana.me/2020/12/15/read-secret-from-azure-key-vault-using-key-vault-rest-api-through-postman/) - Read Secret from Azure Key Vault using Key Vault Rest API through Postman.
- [dirkjanm.io/azure-ad-privilege-escalation-application-admin](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/) - Azure AD privilege escalation - Taking over default application permissions as Application Admin.
- [azure.enterprisesecurity.io](https://azure.enterprisesecurity.io/) - Introduction to Azure Penetration Testing class
- [github.com/Kyuu-Ji/Awesome-Azure-Pentest](https://github.com/Kyuu-Ji/Awesome-Azure-Pentest) - A collection of resources, tools and more for penetration testing and securing Microsofts cloud platform Azure.
- [blog.checkpoint.com/privilege-escalation-in-azure-](https://blog-checkpoint-com.cdn.ampproject.org/c/s/blog.checkpoint.com/2022/06/08/privilege-escalation-in-azure-keep-your-enemies-close-and-your-permissions-closer/amp/) - Privilege Escalation in Azure: Keep your enemies close, and your permissions closer.
- [chowdera.com/azure](https://chowdera.com/2022/04/202204202153332308.html) - use curl to obtain the value in secrets in key vault.
- [bhavsec.com/posts/intro-to-azure-pentesting](https://bhavsec.com/posts/intro-to-azure-pentesting/) - Introduction to Azure Pentesting.
- [docs.microsoft.com/en-us/python/api/overview/azure/](https://docs.microsoft.com/en-us/python/api/overview/azure/keyvault-secrets-readme?view=azure-python) - Azure Key Vault Secrets client libraries python.
- [microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow) - samples how to access with tokens azure.
- [pypi.org/project/azure-keyvault-secrets](https://pypi.org/project/azure-keyvault-secrets/) - Azure Key Vault Secrets client library for Python Examples.
- [docs.microsoft.com/en-us/samples/azure/azure-sdk-for-python/keyvault-keys-samples](https://docs.microsoft.com/en-us/samples/azure/azure-sdk-for-python/keyvault-keys-samples/) - Azure key access samples.
- \[azuresdkdocs.blob.core.windows.net/$web/python/azure-identity](https://azuresdkdocs.blob.core.windows.net/$web/python/azure-identity/1.0.0/index.html#id2) - Azure key access samples.
- [kevinhakanson.com/2020-04-22-exploring-the-microsoft-graph-api-from-azure-cloud-shell](https://kevinhakanson.com/2020-04-22-exploring-the-microsoft-graph-api-from-azure-cloud-shell) - Exploring the Microsoft Graph API from Azure Cloud Shell
- [itd.sog.unc.edu/knowledge-base/article/simple-php-microsoft-graph-application](https://itd.sog.unc.edu/knowledge-base/article/simple-php-microsoft-graph-application) - Simple PHP Microsoft Graph Application
- [azureossd.github.io/2021/06/07/authsettingsv2-graph](https://azureossd.github.io/2021/06/07/authsettingsv2-graph/) - Accessing Microsoft Graph with App Service Auth V2.
- [edureka.co/getting-insufficient-privileges-error-trying-access-azure](https://www.edureka.co/community/50583/getting-insufficient-privileges-error-trying-access-azure) - I am getting Insufficient Privileges error when trying to access Azure Graph APIs.
- [medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines](https://medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines-ed1f8871da56) - Moving laterally between Azure AD joined machines.

## Pentesting Cloud - Azure - Tools

- [github.com/aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit) - Cloud Security Posture Management (CSPM) AWS, GCP, AZURE.
- [github.com/Azure/Stormspotter](https://github.com/Azure/Stormspotter) - Azure Red Team tool for graphing Azure and Azure Active Directory objects.
- [github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-Cloud Security Auditing Tool.
- [github.com/SygniaLabs/security-cloud-scout](https://github.com/SygniaLabs/security-cloud-scout) - AWS - AZURE, Cloud Scout is a plugin which works on top of BloodHound, leveraging its visualization capabilities in order to visualize cross platform attack paths.
- [github.com/cyberark/SkyArk](https://github.com/cyberark/SkyArk) - SkyArk helps to discover, assess and secure the most privileged entities in Azure and AWS.
- [github.com/kh4sh3i/cloud-penetration-testing](https://github.com/kh4sh3i/cloud-penetration-testing) - A curated list of cloud pentesting resource, contains AWS, Azure, Google Cloud.
- [github.com/blacklanternsecurity/offensive-azure](https://github.com/blacklanternsecurity/offensive-azure) - Collection of offensive tools targeting Microsoft Azure.
- [github.com/rvrsh3ll/TokenTactics](https://github.com/rvrsh3ll/TokenTactics) - Azure JWT Token Manipulation Toolset.

## Pentesting - General

\[\[1 - Pentesting\]\]

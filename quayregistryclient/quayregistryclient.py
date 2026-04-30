#!/usr/bin/env python3
#  author peyrard.johann@gmail.com



from urllib.parse import urlencode, quote_plus
import requests, json, argparse, sys, hashlib, re, signal,ssl, socket, os, base64

DEFAULT_PORT=443
DEFAULT_PROTOCOL="https://"
EXIT_TAG_NOT_FOUND=3
ssl_already_verified=0
debug=None
VERSION = "0.3"

# VERSION = "0.3" Adding quayapi stuff related to create delete changepassword of a user

def signal_handler(sig, frame):
    sys.exit(0)


def printstderr(mystr):
    print(mystr, file=sys. stderr)
    

def getservercertificate(registry_url, Port):
    try:
        # 1. Setup context to ignore validation so we can grab the certs anyway
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        pem_chain = []  

        # 3. Connect and wrap the socket
        with socket.create_connection((registry_url, int(Port)), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=registry_url) as ssock: 
                
                # 4. Use get_unverified_chain() for Python 3.10+
                chain = ssock.get_unverified_chain()
                
                if not chain:
                    print("No certificates returned by the server.")
                    return None
                
                # Convert each DER certificate in the chain to PEM
                for cert in chain:
                    pem_cert = ssl.DER_cert_to_PEM_cert(cert)
                    pem_chain.append(pem_cert)
        
        cert_pem = "\n".join(pem_chain)
        
        print(cert_pem)

        if checkhttpsconnection(registry_url,Port)==0:
            printstderr("You might want to add it to your system trust store by adding it to")
            printstderr("/etc/pki/ca-trust/source/anchors/")
            printstderr("and running 'sudo update-ca-trust'")
        else:
            printstderr("This server certificate is trusted locally.")
        return cert_pem

    except Exception as e: 
        # 6. Catch the actual exception 'e' so you know exactly what broke
        print(f"Error: Could not retrieve certificates from {registry_url} on port {Port}.")
        print(f"Details: {e}")
        sys.exit(1)

def checkhttpsconnection(registry_url, port):
    global ssl_already_verified
    if ssl_already_verified==1:
        return ssl_already_verified
    try:
        response = requests.get("https://"+registry_url+":"+str(port) , timeout=5)
        ssl_already_verified=1
        return(ssl_already_verified)
    except requests.exceptions.SSLError:
        printstderr("The server certificate is NOT trusted locally.")
        return(0)
    except requests.exceptions.RequestException as e:
        printstderr(f"An unrelated error occurred: {e}")
        return(0)
    
def checkssl(registry_url,Port):
    cert_pem = ssl.get_server_certificate((registry_url,Port))

def log_python_request_curl_transform(method, url, headers, data=None):
    curl_cmd = f"curl -X {method} '{url}' -H 'Content-Type: application/json' -H 'Accept: application/json' -H 'Authorization: Bearer {headers['Authorization'].split(' ')[1]}'"
    if data:
        curl_cmd += f" -d '{data}'"
    print(f"# {curl_cmd}")
    #response = requests.request(method, url, headers=headers, data=data)
    #return response
    
    
def quayapidiscovery(registry_url,Port,token):
    if debug:
        printstderr("# quayapidiscovery")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)
    
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
    url=url_short+"/api/v1/discovery"
    printstderr("quayapidiscovery")
    if debug:
        log_python_request_curl_transform("GET",url,headers)
    response = requests.get(url, headers=headers)
    print(response.text)
    
def browseapi(registry_url,Port,token,apipath):
    if debug:
        printstderr("# browseapi")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    #token=getToken(registry_url, username, password,Port)
    #token2=getTokenForImageScope(registry_url, username, password,Port,imageName)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
#    url=url_short+"/api/v1/repository/adminadmin/"+imageName+"/manifest"
#    url=url_short+"/api/v1/user/"
    url=url_short+apipath

    if debug:
        log_python_request_curl_transform("GET",url,headers)    
    response = requests.get(url, headers=headers)
    print(response.text)
    

def quayapi_delete_api_v1_superuser_users(registry_url,Port,token,username):
    if debug:
        printstderr("# quayapi_delete_api_v1_superuser_users")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)
    apipath="/api/v1/superuser/users/"+username
    #token=getToken(registry_url, username, password,Port)
    #token2=getTokenForImageScope(registry_url, username, password,Port,imageName)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
#    url=url_short+"/api/v1/repository/adminadmin/"+imageName+"/manifest"
#    url=url_short+"/api/v1/user/"
    url=url_short+apipath

    if debug:
        log_python_request_curl_transform("DELETE",url,headers)    
    response = requests.delete(url, headers=headers)
    print(response.text)

def quayapi_post_api_v1_superuser_users(registry_url,Port,token,username):
    if debug:
        printstderr("# quayapi_delete_api_v1_superuser_users")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)
    apipath="/api/v1/superuser/users/"
    #token=getToken(registry_url, username, password,Port)
    #token2=getTokenForImageScope(registry_url, username, password,Port,imageName)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    payload = {"username": username}
    url_short="https://"+registry_url+":"+Port
#    url=url_short+"/api/v1/repository/adminadmin/"+imageName+"/manifest"
#    url=url_short+"/api/v1/user/"
    url=url_short+apipath

    if debug:
        log_python_request_curl_transform("POST",url,headers)    
    response = requests.post(url, headers=headers, json=payload)
    print(response.text)

def quayapi_put_api_v1_superuser_users(registry_url,Port,token,username,password):
    if debug:
        printstderr("# quayapi_put_api_v1_superuser_users")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)
    apipath="/api/v1/superuser/users/"+username
    #token=getToken(registry_url, username, password,Port)
    #token2=getTokenForImageScope(registry_url, username, password,Port,imageName)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    payload = {"password": password}
    url_short="https://"+registry_url+":"+Port
    url=url_short+apipath

    if debug:
        log_python_request_curl_transform("PUT",url,headers)    
    response = requests.put(url, headers=headers, json=payload)
    print(response.text)

    

def listcatalog(registry_url, username, password,Port):
    images=None
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)
    
    if username==None and password==None:
        catalog_url = f"https://{registry_url}:{Port}/v2/_catalog"
        response = requests.get(catalog_url)
        if response.status_code == 200:
            #printstderr("200 OK")
            images=fetch_catalog_v2_token(registry_url,Port,None)            
        else:
            printstderr("Failed to get catalog")
            return(0)
    elif username!=None and password!=None:
        token=getToken(registry_url, username, password,Port)
        images=fetch_catalog_v2(registry_url, username, password,Port,token)
    else:
        printstderr("username and password are required for authentication")
        printstderr("anonymous access is tried if no username and password are provided")
        return(0)

    if images==None:
        printstderr("No images has been found")
        return(0)
    for image in sorted(images["repositories"]):
        print(image)


def listtags(registry_url, username, password,Port,imageName):
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    token=getToken(registry_url, username, password,Port)
    token2=getTokenForImageScope(registry_url, username, password,Port,imageName)
    image_tag=get_tag_image(registry_url, username, password,Port,token2,imageName)
    print(json.dumps(image_tag))

def listall(registry_url, username, password,Port):
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    token=getToken(registry_url, username, password,Port)
    #list_image_in_catalog(registry_url, username, password,Port,token)        
    images=fetch_catalog_v2(registry_url, username, password,Port,token)

    for image in sorted(images["repositories"]):
        token2=getTokenForImageScope(registry_url, username, password,Port,image)
        image_tag=get_tag_image(registry_url, username, password,Port,token2,image)

        print("#IMG "+image)
        if image_tag is None:
            continue
        for tag in image_tag["tags"]:
            digest=get_manifest_list_image_digest(registry_url, username, password,Port,token2,image,tag)
            print("#TAG "+image+":"+tag)
            #print("## "+image+"@sha256:"+digest)
            if digest!=None:
                print("#SHA "+image+"@"+digest)                
        print(" ")
        sys.stdout.flush()
        

def getimagedigest(registry_url, username, password,Port,imageName,tag):
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    token=getToken(registry_url, username, password,Port)
    token2=getTokenForImageScope(registry_url, username, password,Port,imageName)
    image_tag=get_tag_image(registry_url, username, password,Port,token2,imageName)
    if tag not in image_tag["tags"]:
        printstderr("tag not found")
        sys.exit(EXIT_TAG_NOT_FOUND)
    manifest=get_manifest_list_image_digest(registry_url, username, password,Port,token2,imageName,tag)
    print(manifest)
    #print(image_tag["tags"])
    #print(json.dumps(image_tag))

def getimagemanifest(registry_url, username, password,Port,imageName,digest):
    if debug:
        printstderr("# getimagemanifest")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    token=getToken(registry_url, username, password,Port)
    token2=getTokenForImageScope(registry_url, username, password,Port,imageName)

    manifest=get_manifestlist(registry_url, username, password,Port,token2,imageName,digest)
    print(manifest, end="")

def getblob(registry_url, username, password,Port,imageName,digest):
    if debug:
        printstderr("# getblob")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    token=getToken(registry_url, username, password,Port)
    token2=getTokenForImageScope(registry_url, username, password,Port,imageName)

    blob=get_blob(registry_url, username, password,Port,token2,imageName,digest)
    print(blob, end="")

    

def listdigest(registry_url, username, password,Port,imageName,token):
    if debug:
        printstderr("# listdigest")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
    url=url_short+"/api/v1/repository/adminadmin/"+imageName+"/manifest"
    if debug:
        log_python_request_curl_transform("GET",url,headers)        
    response = requests.get(url, headers=headers)
    print(response)
    #print(json.loads(response.text))
    #print(response.read())
    
def fetch_catalog_v2(registry_url, username, password,Port,token):
    if debug:
        printstderr("# fetch_catalog_v2")
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    # Set the headers with authentication
    more_image=1
    auth = (username, password)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
    url=url_short+"/v2/_catalog"    

    if debug:
        log_python_request_curl_transform("GET",url,headers)
    response = requests.get(url, headers=headers)
    #print(response.text)
    #print(headers)
    # Check if the response was successful
    if response.status_code == 200:
        images = json.loads(response.text)
        #print("headers: ",response.headers)
        #print(response.headers["Link"])
        while more_image:
            if "Link" in response.headers.keys():
                next_re=re.search('<(.*)>',response.headers["Link"]) 
            else:
                next_re=None
            if next_re:
                next_path=next_re.group(1)
                url=url_short+next_path
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    images_next = json.loads(response.text)
                    #images=images+images_next
                    #print(images_next)
                    images["repositories"]=images["repositories"]+images_next["repositories"]
                    #images.update(images_next)
                else:
                    print("Failed to get next images:", response.status_code)
            else:
                more_image=0 
                #print(images["repositories"])     
    else:
        print("Failed to get images:", response.status_code)
    return(images)

def fetch_catalog_v2_token(registry_url,Port,token):
    # Set the headers with authentication
    more_image=1

    # if we have a token try to use it in the headers
    if token!=None:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': "Bearer "+token
        }    
    else:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }    

    url_short="https://"+registry_url+":"+Port
    url=url_short+"/v2/_catalog"    
 
    response = requests.get(url, headers=headers)
    #print(response.text)
    #print(headers)
    # Check if the response was successful
    if response.status_code == 200:
        try:
            images = json.loads(response.text)
        except json.JSONDecodeError:
            printstderr("Failed to parse JSON response")
            exit(1)
        #print("headers: ",response.headers)
        #print(response.headers["Link"])
        while more_image:
            if "Link" in response.headers.keys():
                next_re=re.search('<(.*)>',response.headers["Link"]) 
            else:
                next_re=None
            if next_re:
                next_path=next_re.group(1)
                url=url_short+next_path
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    images_next = json.loads(response.text)
                    #images=images+images_next
                    #print(images_next)
                    images["repositories"]=images["repositories"]+images_next["repositories"]
                    #images.update(images_next)
                else:
                    print("Failed to get next images:", response.status_code)
            else:
                more_image=0 
                #print(images["repositories"])     
    else:
        print("Failed to get images:", response.status_code)
    return(images)



    

def get_tag_image(registry_url, username, password,Port,token,imageName):
    if debug:
        printstderr("# get_tag_image")
    # Set the headers with authentication
    images=None
    auth = (username, password)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }
    url="https://"+registry_url+":"+Port+"/v2/"+imageName+"/tags/list"
    if debug:
        log_python_request_curl_transform("GET",url,headers)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
       images = json.loads(response.text)
       #print(response.headers)
       #print(response.text)
    else:
        print("Failed to get images:", response.status_code)
        print("Failed to get images:", response.headers)
    return(images)
        


def get_blob(registry_url, username, password,Port,token,imageName,digest):
    m=None
    found=0
    manifestListDigest=None
    blob=""
    auth = (username, password)

    for blob_type in [ 'application/vnd.docker.container.image.v1+json',
                       'application/vnd.docker.image.rootfs.diff.tar.gzip',
                       'application/octet-stream'
                      ]:

        headers =    {
            'Content-Type': 'application/json',
            'Accept': blob_type,
            'Authorization': "Bearer "+token
        }
        url="https://"+registry_url+":"+Port+"/v2/"+imageName+"/blobs/"+digest
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and response.headers['Content-Type'] == blob_type and found==0:
            blob=response.text
            found=1
            break
        
    if (found == 0):
        print("Failed to get blob, status_code: %d header: %s, manifestReturned: %s" % ( response.status_code, response.headers, response.text))
    return(blob)



def get_manifestlist(registry_url, username, password,Port,token,imageName,digest):
    if debug:
        printstderr("# get_manifestlist")
    found=0
    manifestListDigest=None
    manifestReturned=""
    auth = (username, password)

    for manifest_type in [ 'application/vnd.docker.distribution.manifest.list.v2+json',
                           'application/vnd.docker.distribution.manifest.v2+json',
                           'application/vnd.oci.image.index.v1+json',
                           'application/vnd.oci.image.manifest.v1+json']:

        headers =    {
            'Content-Type': 'application/json',
            'Accept': manifest_type,
            'Authorization': "Bearer "+token
        }
        url="https://"+registry_url+":"+Port+"/v2/"+imageName+"/manifests/"+digest
        if debug:
            log_python_request_curl_transform("GET",url,headers)
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and response.headers['Content-Type'] == manifest_type and found==0:
            manifestListDigest=response.text
            found=1
            break
        
    if (found == 0):
        print("Failed to get images, status_code: %d header: %s, manifestReturned: %s" % ( response.status_code, response.headers, manifestReturned))
    return(manifestListDigest)



def get_manifest_list_image_digest(registry_url, username, password,Port,token,imageName,tag):
    if debug:
        printstderr("# get_manifestlist")
    found=0
    manifestListDigest=None
    manifestReturned=""
    auth = (username, password)

    for manifest_type in [ 'application/vnd.docker.distribution.manifest.list.v2+json',
                           'application/vnd.docker.distribution.manifest.v2+json',
                           'application/vnd.oci.image.index.v1+json',
                           'application/vnd.oci.image.manifest.v1+json']:

        headers =    {            
            'Accept': manifest_type,
            'Authorization': "Bearer "+token
        }
        url="https://"+registry_url+":"+Port+"/v2/"+imageName+"/manifests/"+tag
        if debug:
            log_python_request_curl_transform("GET",url,headers)

        response = requests.head(url, headers=headers)
        if response.status_code == 200 and response.headers['Content-Type'] == manifest_type and found==0:
            manifestListDigest=response.headers["Docker-Content-Digest"]
            #print(response.headers)
            found=1
        manifestReturned=manifestReturned+" "+response.headers['Content-Type']                   
    
    if found == 0:
        status_code = response.status_code if response is not None else "N/A"
        headers = response.headers if response is not None else {}
        printstderr(
            "Failed to get digest: status_code=%s headers=%s content_types_seen=%s"
            % (status_code, headers, manifestReturned.strip())
        )
    return manifestListDigest

    if (found == 0):
        print("Failed to get images, status_code: %d header: %s, manifestReturned: %s" % ( response.status_code, response.header, manifestReturned))
    return(manifestListDigest)


def getToken(registry_url, username, password,Port):
    token=None
    auth = (username, password)
    headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' }
    options=  {'account': username , 'service' : registry_url+":"+Port }
    
    options_urlencoded=urlencode(options)
    url="https://"+registry_url+":"+Port+"/v2/auth?"+options_urlencoded
    #print(url)
    response = requests.get(url, auth=auth, headers=headers)
    if response.status_code == 200:
       json_token = json.loads(response.text)
       token=json_token["token"]
    else:
        print("Can not get a token")
        sys.exit(3)
    return token
 
def getTokenForImageScope(registry_url, username, password,Port,imageName):
    token=None
    auth = (username, password)
    headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' }
    options=  {'account': username , 'service' : registry_url+":"+Port, 'scope':'repository:'+imageName+':pull' }
    
    options_urlencoded=urlencode(options)
    url="https://"+registry_url+":"+Port+"/v2/auth?"+options_urlencoded
    #print(url)
    response = requests.get(url, auth=auth, headers=headers)
    if response.status_code == 200:
       json_token = json.loads(response.text)
       token=json_token["token"]
    else:
        print("Can not get a token")
        sys.exit(3)
    return token
 
# curl -X DELETE -H "Authorization: Bearer $TOKEN" https://quay6.tnc.bootcamp416.lab:8443/api/v1/repository/redhat/redhat-operator-index
def deleterepo(registry_url,Port,imageName,token):
    if debug:
        printstderr("# deleterepo")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
#    url=url_short+"/api/v1/repository/adminadmin/"+imageName+"/manifest"
    url=url_short+"/api/v1/repository/"+imageName
    if debug:
        log_python_request_curl_transform("DELETE",url,headers)

    response = requests.delete(url, headers=headers)
    print(response)

def deletetag(registry_url,Port,imageName,token,tag):
    if debug:
        printstderr("# deleterepo")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
    url=url_short+"/api/v1/repository/"+imageName+"/tag/"+tag
    if debug:
        log_python_request_curl_transform("DELETE",url,headers)

    response = requests.delete(url, headers=headers)
    print(response)

    
def setapikeyvalue(registry_url,Port,token,apipath,key,value):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
#    url=url_short+"/api/v1/repository/adminadmin/"+imageName+"/manifest"
    url=url_short+apipath
    payload={key : value}
    if debug:
        printstderr("setapikeyvalue: "+url+" "+json.dumps(headers)+" "+json.dumps(payload))
    response = requests.post(url, headers=headers,json=payload)
    print(response)


    
def deleteallrepo(registry_url,username,password,Port,token):
    tokenuserpass=getToken(registry_url, username, password,Port)
    images=fetch_catalog_v2(registry_url, username, password,Port,tokenuserpass)
    for image in sorted(images["repositories"]):
        print(image)
        deleterepo(registry_url,Port,image,token)



def get_registry_password(file_path, registry_host):
    """
    Extracts credentials from ~/.docker/config.json or compatible files.
    Returns: {'username': '...', 'password': '...'} or {} if not found.
    """
    file_path = os.path.expanduser(file_path)
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, 'r') as f:
            config_json = json.load(f)

        auths = config_json.get("auths", {})
        
        # Try exact match first, then try appending/removing https://
        keys_to_try = [
            registry_host,
            f"https://{registry_host}",
            f"http://{registry_host}",
            registry_host.replace("https://", "").replace("http://", "")
        ]

        reg_data = None
        for k in keys_to_try:
            if k in auths:
                reg_data = auths[k]
                break
        
        if not reg_data:
            return {}

        # Handle 'auth' string (Base64 encoded "user:pass")
        if "auth" in reg_data:
            try:
                decoded_auth = base64.b64decode(reg_data["auth"]).decode('utf-8')
                if ":" in decoded_auth:
                    username, password = decoded_auth.split(":", 1)
                    return {"username": username, "password": password}
            except Exception: pass

        # Handle explicit keys
        if "username" in reg_data and "password" in reg_data:
            return {
                "username": reg_data["username"],
                "password": reg_data["password"]
            }

    except Exception:
        pass

    return {}
    
def display_help():
    print("Usage: %s     " % (sys.argv[0] ))
    print(f"Version: {VERSION}")
    print("Command       ")
    print("  get-server-certificate           : display the pem file of the server ")
    print("")
    print("  browse-api                       : query quay api and display the json ")
    print("  quay-api-discovery               : query the quay api endpoint /api/v1/discovery and output the json ")
    print("    # SUPERUSER API with token required to be passed as <-T token> for authentication")
    print("    quay-api-listuser                : query the quay api endpoint /api/v1/superuser/users/ and output the json ")
    print("    quay-api-delete-user             : delete a user from the quay api endpoint /api/v1/superuser/users/ <-u username> ")
    print("    quay-api-create-user             : create a user from the quay api endpoint /api/v1/superuser/users/ <-u username> ")
    print("    quay-api-change-userpassword     : create a user from the quay api endpoint /api/v1/superuser/users/ <-u username> <-p password>")
    print("")
    print("  list-catalog                    : list all image in a repository querying /v2/_catalog")
    print("  list-tags                       : list all tag for a given image <-i imagename> required ")
    print("  list-all                        : list all image, tag and digest ")
    print("  get-image-manifest              : fetch manifest JSON for an image <-i imagename> <-D digest> required")
    print("  get-image-digest                : give the digest of an image <-i imagename> and <-t tag> required ")
    print("  get-manifest                    : fetch the manifest from an image <-i imagename> <-D digest> required ")
    print("  get-blob                        : fetch a blob for an image <-i imagename> <-D digest> required")
    print("  delete-repo                     : delete one repository <-i imagename> required")
    print("  delete-tag                      : delete one tag <-i imagename> <-t tag> required")
    print("  delete-all-repo                 : delete all repositories (requires --i-am-deleting-all-repo)")
    print("  set-api-key-value               : set one key=value on an API path <-a apipath> <-K key> <-V value> required")
    print("Options            ")
    print("  <-r registry_url>")
    print("  <-u username>    ")
    print("  <-p password>    ")
    print("  <-P tcpPort>     ")
    print("  <-i imageName>   ")
    print("  <-a apipath>     ")
    print("  <-K key>         ")
    print("  <-V value>       ")
    print("  <-t tag>         ")
    print("  <-T token>       ")
    print("  <-D digest>      ")
    print("  <-d>                    : for debugging purpose")
    print("")
    print("Special Options")
    print("  --generate-completion        : generate bash completion script and exit")
    print("                                  (source the output to enable tab completion)")


def generate_bash_completion():
    completion_script = '''# Bash completion for quayregistryclient
# Generated by quayregistryclient --generate-completion
# Source this file: source /path/to/quayregistryclient.bash

_quayregistryclient() {
    local cur prev opts cmd registry port image token username password
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd="${COMP_WORDS[1]}"

    local commands="list-catalog list-tags list-all get-image-digest get-image-manifest get-blob delete-repo delete-tag delete-all-repo browse-api quay-api-discovery quay-api-listuser quay-api-delete-user quay-api-create-user quay-api-change-userpassword set-api-key-value get-server-certificate"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    registry=$(_get_arg_value "-r" "--registry-url")
    port=$(_get_arg_value "-P" "--port")
    image=$(_get_arg_value "-i" "--image-name")
    token=$(_get_arg_value "-T" "--token")
    username=$(_get_arg_value "-u" "--username")
    password=$(_get_arg_value "-p" "--password")

    case "${prev}" in
        -r|--registry-url)
            COMPREPLY=()
            return 0
            ;;
        -i|--image-name)
            if [[ -n "${registry}" && -n "${port}" ]]; then
                _complete_repositories "${registry}" "${port}" "${token}" "${username}" "${password}"
            fi
            return 0
            ;;
        -t|--tag)
            if [[ -n "${registry}" && -n "${port}" && -n "${image}" ]]; then
                _complete_tags "${registry}" "${port}" "${image}" "${token}" "${username}" "${password}"
            fi
            return 0
            ;;
        -T|--token|-u|--username|-p|--password|-P|--port|-D|--digest|-a|--apipath|-K|--key|-V|--value)
            COMPREPLY=()
            return 0
            ;;
        -d|-h)
            COMPREPLY=()
            return 0
            ;;
        *)
            local opts
            opts=$(_get_options_for_command "${cmd}")
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            ;;
    esac
}

_get_arg_value() {
    local short="$1"
    local long="$2"
    local i
    for ((i=1; i<${#COMP_WORDS[@]}; i++)); do
        if [[ "${COMP_WORDS[i]}" == "${short}" || "${COMP_WORDS[i]}" == "${long}" ]]; then
            echo "${COMP_WORDS[i+1]}"
            return
        fi
    done
}

_get_options_for_command() {
    local cmd="$1"
    case "${cmd}" in
        list-catalog)
            echo "-r -P -u -p -d -h"
            ;;
        list-tags)
            echo "-r -P -u -p -i -d -h"
            ;;
        list-all)
            echo "-r -P -u -p -d -h"
            ;;
        get-image-digest)
            echo "-r -P -u -p -i -t -d -h"
            ;;
        get-image-manifest)
            echo "-r -P -u -p -i -D -d -h"
            ;;
        get-blob)
            echo "-r -P -u -p -i -D -d -h"
            ;;
        delete-repo)
            echo "-r -P -i -T -d -h"
            ;;
        delete-tag)
            echo "-r -P -i -t -T -d -h"
            ;;
        delete-all-repo)
            echo "-r -P -u -p -T -d -h"
            ;;
        browse-api)
            echo "-r -P -T -a -d -h"
            ;;
        quay-api-discovery)
            echo "-r -P -T -d -h"
            ;;
        quay-api-listuser)
            echo "-r -P -T -d -h"
            ;;
        quay-api-delete-user)
            echo "-r -P -T -u -d -h"
            ;;
        quay-api-create-user)
            echo "-r -P -T -u -d -h"
            ;;
        quay-api-change-userpassword)
            echo "-r -P -T -u -p -d -h"
            ;;
        set-api-key-value)
            echo "-r -P -T -a -K -V -d -h"
            ;;
        get-server-certificate)
            echo "-r -P -d -h"
            ;;
        *)
            echo "-r -P -u -p -i -t -T -D -a -K -V -d -h"
            ;;
    esac
}

_complete_repositories() {
    local registry="$1"
    local port="$2"
    local token="$3"
    local username="$4"
    local password="$5"
    local repos

    if [[ -z "${token}" ]]; then
        token=$(_get_token "${registry}" "${port}" "${username}" "${password}")
    fi

    if [[ -z "${token}" ]]; then
        echo "Error: No token available. Provide -T token or configure ~/.docker/config.json" >&2
        COMPREPLY=()
        return 1
    fi

    repos=$(python3 -c "
import requests, json, sys
try:
    headers = {'Authorization': 'Bearer ${token}'}
    response = requests.get('https://${registry}:${port}/v2/_catalog', headers=headers, timeout=5)
    if response.status_code == 200:
        data = json.loads(response.text)
        print(' '.join(data.get('repositories', [])))
    else:
        sys.exit(1)
except Exception as e:
    sys.exit(1)
" 2>&1)

    if [[ $? -eq 0 && -n "${repos}" ]]; then
        COMPREPLY=( $(compgen -W "${repos}" -- "${cur}") )
    else
        echo "Error: Failed to fetch repositories from ${registry}:${port}" >&2
        COMPREPLY=()
    fi
}

_complete_tags() {
    local registry="$1"
    local port="$2"
    local image="$3"
    local token="$4"
    local username="$5"
    local password="$6"
    local tags

    if [[ -z "${token}" ]]; then
        token=$(_get_token "${registry}" "${port}" "${username}" "${password}")
    fi

    if [[ -z "${token}" ]]; then
        echo "Error: No token available. Provide -T token or configure ~/.docker/config.json" >&2
        COMPREPLY=()
        return 1
    fi

    tags=$(python3 -c "
import requests, json, sys
try:
    headers = {'Authorization': 'Bearer ${token}'}
    response = requests.get('https://${registry}:${port}/v2/${image}/tags/list', headers=headers, timeout=5)
    if response.status_code == 200:
        data = json.loads(response.text)
        print(' '.join(data.get('tags', [])))
    else:
        sys.exit(1)
except Exception as e:
    sys.exit(1)
" 2>&1)

    if [[ $? -eq 0 && -n "${tags}" ]]; then
        COMPREPLY=( $(compgen -W "${tags}" -- "${cur}") )
    else
        echo "Error: Failed to fetch tags for ${image} from ${registry}:${port}" >&2
        COMPREPLY=()
    fi
}

_get_token() {
    local registry="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local config_file="${HOME}/.docker/config.json"

    if [[ -z "${username}" || -z "${password}" ]]; then
        if [[ -f "${config_file}" ]]; then
            local creds
            creds=$(python3 -c "
import json, base64, sys
try:
    with open('${config_file}', 'r') as f:
        config = json.load(f)
    auths = config.get('auths', {})
    for key in ['${registry}:${port}', '${registry}', 'https://${registry}', 'http://${registry}']:
        if key in auths:
            auth_data = auths[key]
            if 'auth' in auth_data:
                decoded = base64.b64decode(auth_data['auth']).decode('utf-8')
                if ':' in decoded:
                    print(decoded)
                    sys.exit(0)
            if 'username' in auth_data and 'password' in auth_data:
                print(auth_data['username'] + ':' + auth_data['password'])
                sys.exit(0)
except Exception:
    pass
sys.exit(1)
" 2>/dev/null)
            if [[ $? -eq 0 && -n "${creds}" ]]; then
                username="${creds%%:*}"
                password="${creds#*:}"
            fi
        fi
    fi

    if [[ -n "${username}" && -n "${password}" ]]; then
        python3 -c "
import requests, json, sys, base64
try:
    auth = ('${username}', '${password}')
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    options = {'account': '${username}', 'service': '${registry}:${port}'}
    from urllib.parse import urlencode
    url = 'https://${registry}:${port}/v2/auth?' + urlencode(options)
    response = requests.get(url, auth=auth, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.text)
        print(data.get('token', ''))
except Exception:
    sys.exit(1)
" 2>/dev/null
    fi
}

complete -F _quayregistryclient quayregistryclient
'''
    print(completion_script)


def create_parser():
    parser = argparse.ArgumentParser(
        prog='quayregistryclient',
        description='Quay Registry Client - CLI tool for container image registry management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    parser.add_argument('-r', '--registry-url', help='Registry URL (e.g., quay.io, myregistry.local)')
    parser.add_argument('-P', '--port', default='443', help='TCP Port (default: 443)')
    parser.add_argument('-u', '--username', help='Registry username')
    parser.add_argument('-p', '--password', help='Registry password')
    parser.add_argument('-i', '--image-name', help='Image name')
    parser.add_argument('-t', '--tag', default='latest', help='Tag name (default: latest)')
    parser.add_argument('-T', '--token', help='Bearer token')
    parser.add_argument('-D', '--digest', help='Image digest')
    parser.add_argument('-a', '--apipath', help='API path')
    parser.add_argument('-K', '--key', help='Key for set-api-key-value')
    parser.add_argument('-V', '--value', help='Value for set-api-key-value')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--generate-completion', action='store_true', help='Generate bash completion script and exit')
    parser.add_argument('--i-am-deleting-all-repo', action='store_true', help='Required for delete-all-repo command')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    sp_catalog = subparsers.add_parser('list-catalog', help='List all images in the registry', add_help=False)
    sp_catalog.add_argument('-r', '--registry-url', required=True)
    sp_catalog.add_argument('-P', '--port', default='443')
    sp_catalog.add_argument('-u', '--username')
    sp_catalog.add_argument('-p', '--password')
    sp_catalog.add_argument('-d', '--debug', action='store_true')

    sp_tags = subparsers.add_parser('list-tags', help='List all tags for an image', add_help=False)
    sp_tags.add_argument('-r', '--registry-url', required=True)
    sp_tags.add_argument('-P', '--port', default='443')
    sp_tags.add_argument('-u', '--username')
    sp_tags.add_argument('-p', '--password')
    sp_tags.add_argument('-i', '--image-name', required=True)
    sp_tags.add_argument('-d', '--debug', action='store_true')

    sp_all = subparsers.add_parser('list-all', help='List all images, tags and digests', add_help=False)
    sp_all.add_argument('-r', '--registry-url', required=True)
    sp_all.add_argument('-P', '--port', default='443')
    sp_all.add_argument('-u', '--username')
    sp_all.add_argument('-p', '--password')
    sp_all.add_argument('-d', '--debug', action='store_true')

    sp_digest = subparsers.add_parser('get-image-digest', help='Get the digest of an image', add_help=False)
    sp_digest.add_argument('-r', '--registry-url', required=True)
    sp_digest.add_argument('-P', '--port', required=True)
    sp_digest.add_argument('-u', '--username')
    sp_digest.add_argument('-p', '--password')
    sp_digest.add_argument('-i', '--image-name', required=True)
    sp_digest.add_argument('-t', '--tag', default='latest')
    sp_digest.add_argument('-d', '--debug', action='store_true')

    sp_manifest = subparsers.add_parser('get-image-manifest', help='Get the manifest JSON for an image', add_help=False)
    sp_manifest.add_argument('-r', '--registry-url', required=True)
    sp_manifest.add_argument('-P', '--port', default='443')
    sp_manifest.add_argument('-u', '--username')
    sp_manifest.add_argument('-p', '--password')
    sp_manifest.add_argument('-i', '--image-name', required=True)
    sp_manifest.add_argument('-D', '--digest', required=True)
    sp_manifest.add_argument('-d', '--debug', action='store_true')

    sp_blob = subparsers.add_parser('get-blob', help='Get a blob for an image', add_help=False)
    sp_blob.add_argument('-r', '--registry-url', required=True)
    sp_blob.add_argument('-P', '--port', default='443')
    sp_blob.add_argument('-u', '--username')
    sp_blob.add_argument('-p', '--password')
    sp_blob.add_argument('-i', '--image-name', required=True)
    sp_blob.add_argument('-D', '--digest', required=True)
    sp_blob.add_argument('-d', '--debug', action='store_true')

    sp_delrepo = subparsers.add_parser('delete-repo', help='Delete a repository', add_help=False)
    sp_delrepo.add_argument('-r', '--registry-url', required=True)
    sp_delrepo.add_argument('-P', '--port', default='443')
    sp_delrepo.add_argument('-i', '--image-name', required=True)
    sp_delrepo.add_argument('-T', '--token', required=True)
    sp_delrepo.add_argument('-d', '--debug', action='store_true')

    sp_deltag = subparsers.add_parser('delete-tag', help='Delete a tag', add_help=False)
    sp_deltag.add_argument('-r', '--registry-url', required=True)
    sp_deltag.add_argument('-P', '--port', default='443')
    sp_deltag.add_argument('-i', '--image-name', required=True)
    sp_deltag.add_argument('-t', '--tag', required=True)
    sp_deltag.add_argument('-T', '--token', required=True)
    sp_deltag.add_argument('-d', '--debug', action='store_true')

    sp_delall = subparsers.add_parser('delete-all-repo', help='Delete all repositories (destructive)', add_help=False)
    sp_delall.add_argument('-r', '--registry-url', required=True)
    sp_delall.add_argument('-P', '--port', default='443')
    sp_delall.add_argument('-u', '--username')
    sp_delall.add_argument('-p', '--password')
    sp_delall.add_argument('-T', '--token', required=True)
    sp_delall.add_argument('--i-am-deleting-all-repo', action='store_true')
    sp_delall.add_argument('-d', '--debug', action='store_true')

    sp_browse = subparsers.add_parser('browse-api', help='Query Quay API and display JSON', add_help=False)
    sp_browse.add_argument('-r', '--registry-url', required=True)
    sp_browse.add_argument('-P', '--port', default='443')
    sp_browse.add_argument('-T', '--token', required=True)
    sp_browse.add_argument('-a', '--apipath', required=True)
    sp_browse.add_argument('-d', '--debug', action='store_true')

    sp_discovery = subparsers.add_parser('quay-api-discovery', help='Query Quay API discovery endpoint', add_help=False)
    sp_discovery.add_argument('-r', '--registry-url', required=True)
    sp_discovery.add_argument('-P', '--port', default='443')
    sp_discovery.add_argument('-T', '--token', required=True)
    sp_discovery.add_argument('-d', '--debug', action='store_true')

    sp_listuser = subparsers.add_parser('quay-api-listuser', help='List Quay users via superuser API', add_help=False)
    sp_listuser.add_argument('-r', '--registry-url', required=True)
    sp_listuser.add_argument('-P', '--port', default='443')
    sp_listuser.add_argument('-T', '--token', required=True)
    sp_listuser.add_argument('-d', '--debug', action='store_true')

    sp_deluser = subparsers.add_parser('quay-api-delete-user', help='Delete a Quay user via superuser API', add_help=False)
    sp_deluser.add_argument('-r', '--registry-url', required=True)
    sp_deluser.add_argument('-P', '--port', default='443')
    sp_deluser.add_argument('-T', '--token', required=True)
    sp_deluser.add_argument('-u', '--username', required=True)
    sp_deluser.add_argument('-d', '--debug', action='store_true')

    sp_createuser = subparsers.add_parser('quay-api-create-user', help='Create a Quay user via superuser API', add_help=False)
    sp_createuser.add_argument('-r', '--registry-url', required=True)
    sp_createuser.add_argument('-P', '--port', default='443')
    sp_createuser.add_argument('-T', '--token', required=True)
    sp_createuser.add_argument('-u', '--username', required=True)
    sp_createuser.add_argument('-d', '--debug', action='store_true')

    sp_changepwd = subparsers.add_parser('quay-api-change-userpassword', help='Change Quay user password via superuser API', add_help=False)
    sp_changepwd.add_argument('-r', '--registry-url', required=True)
    sp_changepwd.add_argument('-P', '--port', default='443')
    sp_changepwd.add_argument('-T', '--token', required=True)
    sp_changepwd.add_argument('-u', '--username', required=True)
    sp_changepwd.add_argument('-p', '--password', required=True)
    sp_changepwd.add_argument('-d', '--debug', action='store_true')

    sp_setkey = subparsers.add_parser('set-api-key-value', help='Set key=value on an API path', add_help=False)
    sp_setkey.add_argument('-r', '--registry-url', required=True)
    sp_setkey.add_argument('-P', '--port', default='443')
    sp_setkey.add_argument('-T', '--token', required=True)
    sp_setkey.add_argument('-a', '--apipath', required=True)
    sp_setkey.add_argument('-K', '--key', required=True)
    sp_setkey.add_argument('-V', '--value', required=True)
    sp_setkey.add_argument('-d', '--debug', action='store_true')

    sp_cert = subparsers.add_parser('get-server-certificate', help='Display the server SSL certificate', add_help=False)
    sp_cert.add_argument('-r', '--registry-url', required=True)
    sp_cert.add_argument('-P', '--port', default='443')
    sp_cert.add_argument('-d', '--debug', action='store_true')

    sp_interactive = subparsers.add_parser('interactive', help='Launch interactive ncurses interface', add_help=False)
    sp_interactive.add_argument('-r', '--registry-url', required=True)
    sp_interactive.add_argument('-P', '--port', default='443')
    sp_interactive.add_argument('-u', '--username')
    sp_interactive.add_argument('-p', '--password')
    sp_interactive.add_argument('-d', '--debug', action='store_true')

    return parser

import curses
import json


class TreeNode:
    def __init__(self, name, node_type, parent=None, data=None):
        self.name = name
        self.node_type = node_type
        self.parent = parent
        self.data = data
        self.children = []
        self.expanded = False
        self.loaded = False


class QueryLoop:
    def __init__(self, registry_url, port, username, password, debug=False):
        self.registry_url = registry_url
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
        self.token = None
        self.root = None
        self.visible_nodes = []
        self.selected_idx = 0

    def authenticate(self):
        if not self.username or not self.password:
            return False
        try:
            self.token = getToken(self.registry_url, self.username, self.password, self.port)
            return True
        except Exception:
            return False

    def fetch_catalog(self):
        if not self.token:
            if not self.authenticate():
                return []
        try:
            images = fetch_catalog_v2(self.registry_url, self.username, self.password, self.port, self.token)
            if images and "repositories" in images:
                return sorted(images["repositories"])
            return []
        except Exception:
            return []

    def fetch_tags(self, repo_name):
        if not self.token:
            if not self.authenticate():
                return []
        try:
            token2 = getTokenForImageScope(self.registry_url, self.username, self.password, self.port, repo_name)
            tags_data = get_tag_image(self.registry_url, self.username, self.password, self.port, token2, repo_name)
            if tags_data and "tags" in tags_data:
                return tags_data["tags"]
            return []
        except Exception:
            return []

    def fetch_digest(self, repo_name, tag):
        if not self.token:
            return None
        try:
            token2 = getTokenForImageScope(self.registry_url, self.username, self.password, self.port, repo_name)
            digest = get_manifest_list_image_digest(self.registry_url, self.username, self.password, self.port, token2, repo_name, tag)
            return digest
        except Exception:
            return None

    def fetch_image_info(self, repo_name):
        if not self.token:
            if not self.authenticate():
                return None
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': "Bearer " + self.token
            }
            url = f"https://{self.registry_url}:{self.port}/api/v1/repository/{repo_name}"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def format_size(self, size_bytes):
        if size_bytes is None:
            return "?"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f}PB"

    def format_date(self, date_str):
        if not date_str:
            return "?"
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d")
        except:
            return date_str[:10] if date_str else "?"

    def calculate_image_size(self, repo_name):
        if not self.token:
            return None
        try:
            tags = self.fetch_tags(repo_name)
            if not tags:
                return None
            total_size = 0
            for tag in tags[:3]:
                digest = self.fetch_digest(repo_name, tag)
                if not digest:
                    continue
                manifest = self.fetch_manifest(repo_name, digest)
                if not manifest:
                    continue
                if manifest.get("schemaVersion") == 2:
                    media_type = manifest.get("mediaType", "")
                    if "manifest.list" in media_type or "image.index" in media_type:
                        for m in manifest.get("manifests", []):
                            m_digest = m.get("digest", "")
                            if m_digest:
                                m_manifest = self.fetch_manifest(repo_name, m_digest)
                                if m_manifest:
                                    if "config" in m_manifest:
                                        total_size += m_manifest.get("config", {}).get("size", 0)
                                    if "layers" in m_manifest:
                                        for layer in m_manifest.get("layers", []):
                                            total_size += layer.get("size", 0)
                    else:
                        if "config" in manifest:
                            total_size += manifest.get("config", {}).get("size", 0)
                        if "layers" in manifest:
                            for layer in manifest.get("layers", []):
                                total_size += layer.get("size", 0)
            return total_size if total_size > 0 else None
        except Exception as e:
            return None

    def fetch_manifest(self, repo_name, digest):
        if not self.token:
            return None
        try:
            token2 = getTokenForImageScope(self.registry_url, self.username, self.password, self.port, repo_name)
            manifest = get_manifestlist(self.registry_url, self.username, self.password, self.port, token2, repo_name, digest)
            if manifest:
                return json.loads(manifest)
            return None
        except Exception:
            return None

    def build_tree(self):
        repos = self.fetch_catalog()
        if not repos:
            return

        self.root = TreeNode(self.registry_url, "registry", None, {"port": self.port})
        self.root.expanded = True

        dirs = {}
        for repo in repos:
            parts = repo.split('/')
            if len(parts) >= 2:
                dir_name = parts[0]
                img_name = '/'.join(parts[1:])
                if dir_name not in dirs:
                    dirs[dir_name] = TreeNode(dir_name + "/", "directory", self.root)
                img_data = {"repo": repo}
                img_node = TreeNode(img_name, "image", dirs[dir_name], img_data)
                dirs[dir_name].children.append(img_node)
            else:
                img_data = {"repo": repo}
                img_node = TreeNode(repo, "image", self.root, img_data)
                self.root.children.append(img_node)

        for dir_node in dirs.values():
            self.root.children.append(dir_node)

        self.root.children.sort(key=lambda x: x.name)

    def load_node_children(self, node):
        if node.loaded:
            return

        if node.node_type == "image":
            tags = self.fetch_tags(node.data["repo"])
            for tag in tags:
                tag_node = TreeNode(tag, "tag", node, {"repo": node.data["repo"], "tag": tag})
                node.children.append(tag_node)
        elif node.node_type == "tag":
            tag_name = node.data.get("tag", "")
            if tag_name.startswith("sha256-"):
                digest = tag_name
            else:
                digest = self.fetch_digest(node.data["repo"], tag_name)
            if digest:
                node.data["digest"] = digest
                manifest = self.fetch_manifest(node.data["repo"], digest)
                if manifest:
                    if manifest.get("schemaVersion") == 2:
                        media_type = manifest.get("mediaType", "")
                        if "manifest.list" in media_type or "image.index" in media_type:
                            for m in manifest.get("manifests", []):
                                platform = m.get("platform", {})
                                os = platform.get("os", "?")
                                arch = platform.get("architecture", "?")
                                variant = platform.get("variant", "")
                                if variant:
                                    platform_str = f"({os}/{arch}/{variant})"
                                else:
                                    platform_str = f"({os}/{arch})"
                                m_node = TreeNode(f"{m.get('digest', 'unknown')[:20]} {platform_str}", "manifest", node, m)
                                node.children.append(m_node)
                        elif "manifest.v2" in media_type or "image.manifest.v1" in media_type:
                            if "layers" in manifest:
                                for layer in manifest.get("layers", []):
                                    blob_node = TreeNode(layer.get("digest", "unknown")[:30], "blob", node, layer)
                                    node.children.append(blob_node)
                            if "config" in manifest:
                                config = manifest.get("config", {})
                                blob_node = TreeNode(config.get("digest", "unknown")[:30], "blob", node, {"digest": config.get("digest"), "size": config.get("size"), "mediaType": config.get("mediaType")})
                                node.children.append(blob_node)

        elif node.node_type == "manifest":
            manifest_digest = node.data.get("digest", "")
            if manifest_digest:
                repo = node.parent.data.get("repo") if node.parent and node.parent.data else None
                if repo:
                    manifest = self.fetch_manifest(repo, manifest_digest)
                    if manifest:
                        media_type = manifest.get("mediaType", "")
                        if "manifest.v2" in media_type or "image.manifest.v1" in media_type:
                            if "layers" in manifest:
                                for layer in manifest.get("layers", []):
                                    media_type = layer.get("mediaType", "")
                                    short_type = media_type.split('.')[-1] if media_type else "?"
                                    blob_node = TreeNode(f"{layer.get('digest', 'unknown')[:30]} ({short_type})", "blob", node, layer)
                                    node.children.append(blob_node)
                            if "config" in manifest:
                                config = manifest.get("config", {})
                                media_type = config.get("mediaType", "")
                                short_type = media_type.split('.')[-1] if media_type else "?"
                                blob_node = TreeNode(f"{config.get('digest', 'unknown')[:30]} ({short_type})", "blob", node, {"digest": config.get("digest"), "size": config.get("size"), "mediaType": config.get("mediaType")})
                                node.children.append(blob_node)

        node.loaded = True

    def expand_to_blobs(self, node):
        if node.node_type == "image":
            self.load_node_children(node)
            for child in node.children:
                if child.node_type == "tag":
                    child.expanded = True
                    self.load_node_children(child)
        elif node.node_type == "directory":
            self.load_node_children(node)
            for child in node.children:
                if child.node_type in ("directory", "image"):
                    child.expanded = True
                    self.expand_to_blobs(child)
        elif node.node_type == "tag":
            self.load_node_children(node)
            for child in node.children:
                if child.node_type == "manifest":
                    child.expanded = True
                    self.load_node_children(child)

    def get_visible_nodes(self):
        self.visible_nodes = []
        self._collect_visible(self.root, 0)
        return self.visible_nodes

    def _collect_visible(self, node, depth):
        if not node:
            return
        self.visible_nodes.append((node, depth))
        if node.expanded:
            self.load_node_children(node)
            for child in node.children:
                self._collect_visible(child, depth + 1)

    def run(self, stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)

        if not self.username or not self.password:
            self.get_credentials(stdscr)

        if not self.authenticate():
            self.show_message(stdscr, "Authentication failed. Check credentials.", error=True)
            return

        self.build_tree()
        if not self.root or not self.root.children:
            self.show_message(stdscr, "No repositories found.", error=True)
            return

        self.tree_view(stdscr)

    def get_credentials(self, stdscr):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h // 2 - 5

        stdscr.addstr(y, w // 2 - 15, "Quay Registry Client - Login", curses.A_BOLD)
        stdscr.addstr(y + 2, w // 2 - 10, "Username: ")
        stdscr.clrtoeol()
        curses.echo()
        username = stdscr.getstr(y + 2, w // 2 + 1, 30).decode('utf-8')
        stdscr.addstr(y + 4, w // 2 - 10, "Password: ")
        stdscr.clrtoeol()
        password = stdscr.getstr(y + 4, w // 2 + 1, 30, ord('*')).decode('utf-8')
        curses.noecho()

        self.username = username
        self.password = password
        stdscr.clear()

    def tree_view(self, stdscr):
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            title = f"Registry Browser - {self.registry_url}:{self.port}"
            stdscr.addstr(0, (w - len(title)) // 2, title, curses.A_BOLD | curses.color_pair(1))
            stdscr.addstr(1, 0, "=" * (w - 1))

            visible = self.get_visible_nodes()
            if not visible:
                stdscr.addstr(3, 2, "No items to display.", curses.color_pair(3))
            else:
                visible_rows = h - 4
                start_idx = max(0, self.selected_idx - visible_rows // 2)
                end_idx = min(len(visible), start_idx + visible_rows)

                for i in range(start_idx, end_idx):
                    node, depth = visible[i]
                    y = 2 + (i - start_idx)
                    if y >= h - 2:
                        break

                    prefix = "  " * depth
                    icon = "[?]"
                    if node.node_type == "directory":
                        icon = "[-]" if node.expanded else "[+]"
                    elif node.node_type == "image":
                        icon = "[I]"
                        if not hasattr(node, '_tag_count_fetched'):
                            repo = node.data.get("repo", "")
                            if repo and self.token:
                                tags = self.fetch_tags(repo)
                                node._tag_count = len(tags) if tags else 0
                                node._tag_count_fetched = True
                        tag_count = getattr(node, '_tag_count', 0)
                        if tag_count > 0:
                            base_name = node.data.get("display_name", "")
                            if not base_name:
                                base_name = node.name.split(" (")[0] if " (" in node.name else node.name
                                node.data["display_name"] = base_name
                            if f"({tag_count} tags)" not in node.name:
                                node.name = f"{base_name} ({tag_count} tags)"
                    elif node.node_type == "tag":
                        icon = "[T]"
                    elif node.node_type == "blob":
                        icon = "[B]"
                    elif node.node_type == "manifest":
                        icon = "[M]"
                    elif node.node_type == "registry":
                        icon = "[R]"

                    display = f"{prefix}{icon} {node.name}"
                    if i == self.selected_idx:
                        stdscr.addstr(y, 2, display[:w-3], curses.A_REVERSE)
                    else:
                        color = curses.color_pair(1) if node.node_type == "directory" else \
                                curses.color_pair(2) if node.node_type == "image" else \
                                curses.color_pair(4) if node.node_type == "tag" else \
                                curses.color_pair(5) if node.node_type == "manifest" else \
                                curses.color_pair(3) if node.node_type == "blob" else \
                                curses.color_pair(3)
                        stdscr.addstr(y, 2, display[:w-3], color)

            status = "[Space] Expand/Collapse | [Enter] View Details | [q] Quit"
            stdscr.addstr(h - 1, 0, status[:w - 1])

            key = stdscr.getch()

            if key == ord('q'):
                break
            elif key == curses.KEY_UP:
                self.selected_idx = max(0, self.selected_idx - 1)
            elif key == curses.KEY_DOWN:
                self.selected_idx = min(len(visible) - 1, self.selected_idx + 1)
            elif key == ord(' '):
                if 0 <= self.selected_idx < len(visible):
                    node, _ = visible[self.selected_idx]
                    old_expanded = node.expanded
                    if node.node_type == "directory":
                        node.expanded = not node.expanded
                    elif node.node_type == "image":
                        node.expanded = not node.expanded
                        if node.expanded and not old_expanded:
                            self.expand_to_blobs(node)
                    elif node.node_type == "tag":
                        node.expanded = not node.expanded
                        if node.expanded and not old_expanded:
                            self.load_node_children(node)
                    elif node.node_type == "manifest":
                        node.expanded = not node.expanded
                        if node.expanded and not old_expanded:
                            self.load_node_children(node)
                    if not old_expanded:
                        new_visible = self.get_visible_nodes()
                        for i, (n, d) in enumerate(new_visible):
                            if n == node:
                                self.selected_idx = i
                                break
            elif key == ord('\n') or key == curses.KEY_ENTER:
                if 0 <= self.selected_idx < len(visible):
                    node, _ = visible[self.selected_idx]
                    if node.node_type in ("image", "tag", "blob"):
                        self.show_node_details(stdscr, node)

    def show_node_details(self, stdscr, node):
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            title = f"Details: {node.name}"
            stdscr.addstr(0, (w - len(title)) // 2, title, curses.A_BOLD | curses.color_pair(1))
            stdscr.addstr(1, 0, "=" * (w - 1))

            y = 3
            stdscr.addstr(y, 2, f"Type: {node.node_type}", curses.color_pair(2))

            if node.node_type == "image":
                stdscr.addstr(y + 1, 2, f"Repository: {node.data.get('repo', 'N/A')}", curses.color_pair(1))
                tags = self.fetch_tags(node.data.get("repo", ""))
                stdscr.addstr(y + 2, 2, f"Tags ({len(tags)}): {', '.join(tags[:10])}{'...' if len(tags) > 10 else ''}")
                stdscr.addstr(y + 3, 2, "Calculating size...")
                stdscr.refresh()
                size = self.calculate_image_size(node.data.get("repo", ""))
                stdscr.addstr(y + 3, 2, " " * 50)
                if size:
                    stdscr.addstr(y + 3, 2, f"Size: ~{self.format_size(size)}")
                else:
                    stdscr.addstr(y + 3, 2, "Size: unavailable")
            elif node.node_type == "tag":
                stdscr.addstr(y + 1, 2, f"Repository: {node.data.get('repo', 'N/A')}", curses.color_pair(1))
                stdscr.addstr(y + 2, 2, f"Tag: {node.data.get('tag', 'N/A')}", curses.color_pair(4))
                digest = node.data.get("digest", "Loading...")
                stdscr.addstr(y + 3, 2, f"Digest: {digest}", curses.color_pair(3))
            elif node.node_type == "blob":
                stdscr.addstr(y + 1, 2, f"Size: {node.data.get('size', 'N/A')}", curses.color_pair(1))
                stdscr.addstr(y + 2, 2, f"MediaType: {node.data.get('mediaType', 'N/A')}", curses.color_pair(4))

            stdscr.addstr(h - 1, 0, "Press [b] to go back or [q] to quit")

            key = stdscr.getch()
            if key == ord('b') or key == ord('q'):
                break

    def show_message(self, stdscr, message, error=False):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h // 2
        color = curses.color_pair(3) if error else curses.color_pair(2)
        stdscr.addstr(y, (w - len(message)) // 2, message, color)
        stdscr.addstr(y + 2, (w - 20) // 2, "Press any key to exit...")
        stdscr.getch()


def main():
    parser = create_parser()

    if len(sys.argv) > 1 and sys.argv[1] == '--help' and len(sys.argv) == 2:
        display_help()
        sys.exit(0)

    if len(sys.argv) == 1:
        display_help()
        sys.exit(0)

    args, unknown = parser.parse_known_args()

    if args.generate_completion:
        generate_bash_completion()
        sys.exit(0)

    global debug
    debug = 1 if args.debug else None

    registry_url = args.registry_url
    Port = args.port
    username = args.username
    password = args.password
    token = args.token
    imageName = args.image_name
    tag = args.tag
    digest = args.digest
    apipath = args.apipath
    key = args.key
    value = args.value
    i_am_deleting_all_repo = args.i_am_deleting_all_repo

    if not args.command:
        display_help()
        sys.exit(0)           

    if registry_url:
        if "https://" in registry_url:
            registry_url = registry_url.replace("https://", "")
            Port=443
        # We capture the port from registry_url and cleanup registry_url to keep only the host
        pattern = r':(\d+)/$'
        match = re.search(pattern, registry_url)
        if match:
            Port = match.group(1)
            registry_url = registry_url.replace(match.group(0), "")
        pattern = r':(\d+)$'
        match = re.search(pattern, registry_url)
        if match:
            Port = match.group(1)
            registry_url = registry_url.replace(match.group(0), "")
    

    # Find the credentials in the ~/.docker/config.json file
    if registry_url != None and username==None and password==None:
        mydict={}
        clean_url = registry_url
        pattern = r'(/)$'
        match = re.search(pattern, clean_url)
        if match:
          clean_url = clean_url.replace(match.group(0), "")
        
        if registry_url!=None and Port!=None:
            mydict=get_registry_password("~/.docker/config.json",clean_url+":"+str(Port))
        elif registry_url:
            mydict=get_registry_password("~/.docker/config.json",clean_url)
        if (mydict and mydict["username"] and mydict["password"]):
            username=mydict["username"]
            password=mydict["password"]

    if tag==None:
        tag="latest"

    cmd = args.command

    if cmd == "get-server-certificate":
        if not all([registry_url,Port]):
            print(f"Error: missing parameters get-server-certificate(registry_url={registry_url},Port={Port})")
            sys.exit(2)
        getservercertificate(registry_url, Port)
    elif cmd == "quay-api-discovery":
        if not all([registry_url,Port,token]):
            token_val="##maskingToken##" if token is not None else token
            print(f"Error: missing parameters quay-api-discovery(registry_url={registry_url},Port={Port},token={token_val})")
            sys.exit(2)
        quayapidiscovery(registry_url,Port,token)
    elif cmd == "browse-api":
        if not all([registry_url,Port,token,apipath]):
            token_val="##maskingToken##" if token is not None else token
            print(f"Error: missing parameters browse-api(registry_url={registry_url},Port={Port},token={token_val},apipath={apipath})")
            sys.exit(2)
        browseapi(registry_url,Port,token,apipath)
    elif cmd == "quay-api-listuser":
        if not all([registry_url,Port,token]):
            token_val="##maskingToken##" if token is not None else token
            print(f"Error: missing parameters browse-api(registry_url={registry_url},Port={Port},token={token_val}")
            sys.exit(2)
        browseapi(registry_url,Port,token,"/api/v1/superuser/users/")
    elif cmd == "quay-api-delete-user":
        if not all([registry_url,Port,token,username]):
            token_val="##maskingToken##" if token is not None else token
            print(f"Error: missing parameters quay-api-delete-user(registry_url={registry_url},Port={Port},token={token_val},username={username})")
            sys.exit(2)
        quayapi_delete_api_v1_superuser_users(registry_url,Port,token,username)
    elif cmd == "quay-api-create-user":
        if not all([registry_url,Port,token,username]):
            token_val="##maskingToken##" if token is not None else token
            print(f"Error: missing parameters quay-api-create-user(registry_url={registry_url},Port={Port},token={token_val},username={username})")
            sys.exit(2)
        quayapi_post_api_v1_superuser_users(registry_url,Port,token,username)
    elif cmd == "quay-api-change-userpassword":
        if not all([registry_url,Port,token,username,password]):
            token_val="##maskingToken##" if token is not None else token
            print(f"Error: missing parameters quay-api-change-userpassword(registry_url={registry_url},Port={Port},token={token_val},username={username},password={password})")
            sys.exit(2)
        quayapi_put_api_v1_superuser_users(registry_url,Port,token,username,password)
    elif cmd == "list-catalog":
        if not all([registry_url, Port]):
            print(f"Error: missing parameters list-catalog(registry_url={registry_url},Port={Port})")
            sys.exit(2)
        listcatalog(registry_url, username, password,Port)
    elif cmd == "list-tags":
        if not all([registry_url, username, password,Port,imageName]):
            password_val="##maskingPassword##" if password is not None else password
            print(f"Error: missing parameters list-tags(registry_url={registry_url},username={username},password={password_val},Port={Port},imageName={imageName})")
            sys.exit(2)
        listtags(registry_url, username, password,Port,imageName)
    elif cmd == "list-all":
        if not all([registry_url, username, password,Port]):
            password_val="##maskingPassword##" if password is not None else password
            print(f"Error: missing parameters list-all(registry_url={registry_url},Port={Port},username={username},password={password_val})")
            sys.exit(2)
        listall(registry_url, username, password,Port)
    elif cmd == "get-image-digest":
        if not all([registry_url, username, password,Port,imageName,tag]):
            password_val="##maskingPassword##" if password is not None else password
            print(f"Error: missing parameters image-digest(registry_url={registry_url},username={username},password={password_val},Port={Port},imageName={imageName},tag={tag})")
            sys.exit(2)
        getimagedigest(registry_url, username, password,Port,imageName,tag)
    elif cmd == "get-image-manifest":
        if not all([registry_url, username, password,Port,imageName,digest]):
            password_val="##maskingPassword##" if password is not None else password
            print(f"Error: missing parameters image-digest(registry_url={registry_url},username={username},password={password_val},Port={Port},imageName={imageName},digest={digest})")
            sys.exit(2)
        getimagemanifest(registry_url, username, password,Port,imageName,digest)
    elif cmd == "get-blob":
        if not all([registry_url, username, password,Port,imageName,digest]):
            password_val="##maskingPassword##" if password is not None else password
            print(f"Error: missing parameters get-blob(registry_url={registry_url},username={username},password={password_val},Port={Port},imageName={imageName},digest={digest})")
            sys.exit(2)
        getblob(registry_url, username, password,Port,imageName,digest)
    elif cmd == "list-digest":
        if not all([registry_url, username, password,Port,imageName,token]):
            print("Error: missing parameters list-digest(registry_url={registry_url},username={username},password={password},Port={Port},imageName={imageName},token={token})")
            sys.exit(2)
        listdigest(registry_url, username, password,Port,imageName,token)
    elif cmd == "delete-repo":
        if not all([registry_url,imageName,token]):
            print(f"Error: missing parameters delete-repo(registry_url={registry_url},imageName={imageName},token={token})")
            sys.exit(2)
        deleterepo(registry_url, Port,imageName,token)
    elif cmd == "delete-tag":
        if not all([registry_url, Port,imageName,token,tag]):
            print(f"Error: missing parameters delete-tag(registry_url={registry_url},Port={Port},imageName={imageName},token={token},tag={tag})")
            sys.exit(2)
        deletetag(registry_url, Port,imageName,token,tag)
    elif cmd == "set-api-key-value":
        if not all([registry_url, Port,token,apipath,key,value]):
            print(f"Error: missing parameters set-api-key-value(registry_url={registry_url},Port={Port},token={token},apipath={apipath},key={key},value={value})")
            sys.exit(2)
        setapikeyvalue(registry_url, Port,token,apipath,key,value)
    elif cmd == "delete-all-repo":
        if not i_am_deleting_all_repo:
            print("ERROR: SAFETY CHECK FAILED.")
            print("This is a destructive operation that will wipe the entire registry.")
            print("To proceed, you must strictly add the flag: --i-am-deleting-all-repo")
            sys.exit(1)
        if not all([registry_url, username, password,Port,token]):
            password_val="##maskingPassword##" if password is not None else password
            print(f"Error: missing parameters delete-all-repo(registry_url={registry_url},Port={Port},token={token}")
            sys.exit(2)
        deleteallrepo(registry_url, username, password,Port,token)
    elif cmd == "interactive":
        from curses import wrapper
        loop = QueryLoop(registry_url, Port, username, password, debug)
        wrapper(loop.run)
    else:
        print("A command is needed.")
        print("")
        display_help()
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
    def __init__(self, registry_url, port, username, password, debug=False):
        self.registry_url = registry_url
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
        self.token = None
        self.repositories = []
        self.current_view = "main"
        self.selected_idx = 0

    def authenticate(self):
        if not self.username or not self.password:
            return False
        try:
            self.token = getToken(self.registry_url, self.username, self.password, self.port)
            return True
        except Exception:
            return False

    def fetch_catalog(self):
        if not self.token:
            if not self.authenticate():
                return []
        try:
            images = fetch_catalog_v2(self.registry_url, self.username, self.password, self.port, self.token)
            if images and "repositories" in images:
                self.repositories = sorted(images["repositories"])
            return self.repositories
        except Exception:
            return []

    def fetch_tags(self, repo_name):
        if not self.token:
            if not self.authenticate():
                return []
        try:
            token2 = getTokenForImageScope(self.registry_url, self.username, self.password, self.port, repo_name)
            tags_data = get_tag_image(self.registry_url, self.username, self.password, self.port, token2, repo_name)
            if tags_data and "tags" in tags_data:
                return tags_data["tags"]
            return []
        except Exception:
            return []

    def run(self, stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)

        if not self.username or not self.password:
            self.get_credentials(stdscr)

        if not self.authenticate():
            self.show_message(stdscr, "Authentication failed. Check credentials.", error=True)
            return

        while True:
            if self.current_view == "main":
                self.repositories = self.fetch_catalog()
                if not self.repositories:
                    self.show_message(stdscr, "No repositories found.", error=True)
                    return
                self.main_menu(stdscr)
            elif self.current_view == "tags":
                self.tags_view(stdscr)
            elif self.current_view == "quit":
                return

    def get_credentials(self, stdscr):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h // 2 - 5

        stdscr.addstr(y, w // 2 - 15, "Quay Registry Client - Login", curses.A_BOLD)
        stdscr.addstr(y + 2, w // 2 - 10, "Username: ")
        stdscr.clrtoeol()
        curses.echo()
        username = stdscr.getstr(y + 2, w // 2 + 1, 30).decode('utf-8')
        stdscr.addstr(y + 4, w // 2 - 10, "Password: ")
        stdscr.clrtoeol()
        password = stdscr.getstr(y + 4, w // 2 + 1, 30, ord('*')).decode('utf-8')
        curses.noecho()

        self.username = username
        self.password = password
        stdscr.clear()

    def main_menu(self, stdscr):
        while self.current_view == "main":
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            title = f"Repositories - {self.registry_url}:{self.port}"
            stdscr.addstr(0, (w - len(title)) // 2, title, curses.A_BOLD | curses.color_pair(1))
            stdscr.addstr(1, 0, "=" * (w - 1))

            if not self.repositories:
                self.show_message(stdscr, "No repositories found.", error=True)
                return

            visible_rows = h - 4
            start_idx = max(0, self.selected_idx - visible_rows // 2)
            end_idx = min(len(self.repositories), start_idx + visible_rows)

            for i, repo in enumerate(self.repositories[start_idx:end_idx]):
                y = 2 + i
                if y >= h - 2:
                    break
                if start_idx + i == self.selected_idx:
                    stdscr.addstr(y, 2, f"> {repo}", curses.A_REVERSE)
                else:
                    stdscr.addstr(y, 2, f"  {repo}")

            status = f"Total: {len(self.repositories)} | Use arrow keys, Enter to view tags, 'q' to quit"
            stdscr.addstr(h - 1, 0, status[:w - 1])

            key = stdscr.getch()

            if key == ord('q'):
                self.current_view = "quit"
            elif key == curses.KEY_UP:
                self.selected_idx = max(0, self.selected_idx - 1)
            elif key == curses.KEY_DOWN:
                self.selected_idx = min(len(self.repositories) - 1, self.selected_idx + 1)
            elif key == ord('\n') or key == curses.KEY_ENTER:
                if 0 <= self.selected_idx < len(self.repositories):
                    self.current_repo = self.repositories[self.selected_idx]
                    self.current_tags = self.fetch_tags(self.current_repo)
                    self.current_view = "tags"

    def tags_view(self, stdscr):
        while self.current_view == "tags":
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            title = f"Tags - {self.current_repo}"
            stdscr.addstr(0, (w - len(title)) // 2, title, curses.A_BOLD | curses.color_pair(1))
            stdscr.addstr(1, 0, "=" * (w - 1))

            if not self.current_tags:
                stdscr.addstr(3, 2, "No tags found.", curses.color_pair(3))
            else:
                visible_rows = h - 4
                start_idx = max(0, self.selected_idx - visible_rows // 2)
                end_idx = min(len(self.current_tags), start_idx + visible_rows)

                for i, tag in enumerate(self.current_tags[start_idx:end_idx]):
                    y = 2 + i
                    if y >= h - 2:
                        break
                    if start_idx + i == self.selected_idx:
                        stdscr.addstr(y, 2, f"> {tag}", curses.A_REVERSE)
                    else:
                        stdscr.addstr(y, 2, f"  {tag}")

            status = f"Tags: {len(self.current_tags)} | Use arrow keys, 'b' to go back, 'q' to quit"
            stdscr.addstr(h - 1, 0, status[:w - 1])

            key = stdscr.getch()

            if key == ord('q'):
                self.current_view = "quit"
            elif key == ord('b'):
                self.selected_idx = 0
                self.current_view = "main"
            elif key == curses.KEY_UP:
                self.selected_idx = max(0, self.selected_idx - 1)
            elif key == curses.KEY_DOWN:
                self.selected_idx = min(len(self.current_tags) - 1, self.selected_idx + 1)

    def show_message(self, stdscr, message, error=False):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        y = h // 2
        color = curses.color_pair(3) if error else curses.color_pair(2)
        stdscr.addstr(y, (w - len(message)) // 2, message, color)
        stdscr.addstr(y + 2, (w - 20) // 2, "Press any key to exit...")
        stdscr.getch()


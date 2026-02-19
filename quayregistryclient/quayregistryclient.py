#!/usr/bin/env python3
#  author peyrard.johann@gmail.com



from urllib.parse import urlencode, quote_plus
import requests, json, getopt, sys, hashlib, re, signal,ssl, socket, os, base64

DEFAULT_PORT=443
DEFAULT_PROTOCOL="https://"
EXIT_TAG_NOT_FOUND=3
ssl_already_verified=0
debug=None
VERSION = "0.2"


def signal_handler(sig, frame):
    sys.exit(0)



def printstderr(mystr):
    print(mystr, file=sys. stderr)
    
def getservercertificate(registry_url, Port):
    #if checkhttpsconnection(registry_url, Port):
    try:
        cert_pem = ssl.get_server_certificate((registry_url,Port))
    except: 
        print(f"Error: Could not connect to {registry_url} on port {Port}.")
        sys.exit(1) 
    print(cert_pem)

def checkhttpsconnection(registry_url, port):
    global ssl_already_verified
    if ssl_already_verified==1:
        return ssl_already_verified
    try:
        response = requests.get("https://"+registry_url+":"+port , timeout=5)
        ssl_already_verified=1
        return(ssl_already_verified)
    except requests.exceptions.SSLError:
        printstderr("Error: The server certificate is NOT trusted locally.")
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
    
    
def listcatalog(registry_url, username, password,Port):
    if checkhttpsconnection(registry_url,Port)==0:
        return(0)

    token=getToken(registry_url, username, password,Port)
    images=fetch_catalog_v2(registry_url, username, password,Port,token)
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
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': "Bearer "+token
    }    
    url_short="https://"+registry_url+":"+Port
    url=url_short+"/v2/_catalog"    
 
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


def get_registry_password(file_path, registry_url):
    """
    Extracts credentials from ~/.docker/config.json OR a K8s pull-secret file.
    Returns: {'username': '...', 'password': '...'} or {} if not found.
    """
    # Expand path (handles ~/ paths)
    file_path = os.path.expanduser(file_path)
    
    try:
        with open(file_path, 'r') as f:
            config_json = json.load(f)

        auths = config_json.get("auths", {})
        reg_data = auths.get(registry_url)

        if not reg_data:
            return {}

        # 3. Handle 'auth' string (Base64 encoded "user:pass")
        if "auth" in reg_data:
            decoded_auth = base64.b64decode(reg_data["auth"]).decode('utf-8')
            if ":" in decoded_auth:
                username, password = decoded_auth.split(":", 1)
                return {"username": username, "password": password}

        # 4. Handle explicit keys (sometimes used in custom configs)
        if "username" in reg_data and "password" in reg_data:
            return {
                "username": reg_data["username"],
                "password": reg_data["password"]
            }

    except Exception:
        return {}

    return {}

    
def display_help():
    print("Usage: %s     " % (sys.argv[0] ))
    print(f"Version: {VERSION}")
    print("Command       ")
    print("  get-server-certificate  : display the pem file of the server ")
    print("  browse-api              : query quay api and display the json ")
    print("  quay-api-discovery      : query the quay api endpoint /api/v1/discovery and output the json ")
    print("  list-catalog            : list all image in a repository querying /v2/_catalog")
    print("  list-tags               : list all tag for a given image <-i imagename> required ")
    print("  list-all                : list all image, tag and digest ")
    print("  get-image-digest        : give the digest of an image <-i imagename> and <-t tag> required ")
    print("  get-manifest            : fetch the manifest from an image <-i imagename> <-D digest> required ")
    print("  get-blob                : fetch a blob associated with an image <-i imagename> <-D digest> required ")
    print("  delete-repo             : delete a specific image repo <-i imagename> ")
    print("  delete-all-repo         : delete a specific image repo <-i imagename> ")
    print("  set-api-path-key-value  : set a specific key = value to an apipath  ")
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



    
    
        
def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdr:u:p:P:i:t:T:a:K:V:D:",
                                   ["help","registry_url","username","password","Port","imagename","tag","token","apipath","key","value","digest","i-am-deleting-all-repo"])
    except getopt.GetoptError as err:
        print(err)
        sys.exit(2)

    registry_url = None
    Port = None
    username = None
    password = None
    token = None
    imageName=None
    tag=None
    token=None
    apipath=None
    key=None
    value=None
    digest=None
    i_am_deleting_all_repo=False
    global debug
    
    for o, a in opts:
        if o == "-h" or o == "--help":
            display_help()
            sys.exit()
        elif o in ("-r", "--registry_url"):
            registry_url = a
        elif o in ("-u", "--username"):
            username = a
        elif o in ("-p", "--password"):
            password = a
        elif o in ("-P", "--Port"):
            Port = a
        elif o in ("-a", "--apipath"):
            apipath = a
        elif o in ("-i","imagename"):
            imageName = a
        elif o in ("-t","tag"):
            tag = a
        elif o in ("-K","key"):
            key = a
        elif o in ("-V","value"):
            value = a
        elif o in ("-T","token"):
            token = a
        elif o in ("-D","digest"):
            digest = a
        elif o in ("-d"):
            debug = 1
        elif o == "--i-am-deleting-all-repo":
            i_am_deleting_all_repo = True           
            
    if registry_url != None and username==None and password==None:
        mydict={}
        if registry_url!=None and Port!=None:
            mydict=get_registry_password("~/.docker/config.json",registry_url+":"+Port)
        elif registry_url:
            mydict=get_registry_password("~/.docker/config.json",registry_url)
        
        if (mydict and mydict["username"] and mydict["password"]):
            username=mydict["username"]
            password=mydict["password"]


    if "https://" in registry_url:
        registry_url = registry_url.replace("https://", "")
        Port=443

    # We capture the port in group 1, but we target the whole ':digits/' for replacement
    pattern = r':(\d+)/$'
    match = re.search(pattern, registry_url)
    if match:
        Port = match.group(1)
        registry_url = registry_url.replace(match.group(0), "")
    
    if tag==None:
        tag="latest"
        
    if len(args)==0:
        display_help()
        sys.exit(0)


        
    for a in args:
        if a == "get-server-certificate":
            if not all([registry_url,Port]):
                print("Error: missing parameters")
                sys.exit(2)
            getservercertificate(registry_url, Port)
        # BROWSE API
        elif a == "quay-api-discovery":
            if not all([registry_url,Port,token]):
                token="##maskingToken##" if token is not None else token
                print(f"Error: missing parameters quay-api-discovery(registry_url={registry_url},Port={Port},token={token})")
                sys.exit(2)
            quayapidiscovery(registry_url,Port,token)
        # BROWSE API
        elif a == "browse-api":
            if not all([registry_url,Port,token,apipath]):
                token="##maskingToken##" if token is not None else token
                print(f"Error: missing parameters browse-api(registry_url={registry_url},Port={Port},token={token},apipath={apipath})")
                sys.exit(2)
            browseapi(registry_url,Port,token,apipath)
            
        # list catalog v2
        elif a == "list-catalog":
            if not all([registry_url, username, password,Port]):
                print("Error: missing parameters")
                sys.exit(2)
            listcatalog(registry_url, username, password,Port)

        # list tag for an image
        elif a == "list-tags":
            if not all([registry_url, username, password,Port,imageName]):
                password="##maskingPassword##" if password is not None else password
                print(f"Error: missing parameters list-tags(registry_url={registry_url},username={username},password={password},Port={Port},imageName={imageName})")
                sys.exit(2)
            listtags(registry_url, username, password,Port,imageName)

        # list all image
        elif a == "list-all":
            if not all([registry_url, username, password,Port]):
                password="##maskingPassword##" if password is not None else password
                print(f"Error: missing parameters list-all(registry_url={registry_url},Port={Port},username={username},password={password})")
                sys.exit(2)
            listall(registry_url, username, password,Port)

        # GET the digest from an image:tag
        elif a == "get-image-digest":
            if not all([registry_url, username, password,Port,imageName,tag]):
                password="##maskingPassword##" if password is not None else password
                print(f"Error: missing parameters image-digest(registry_url={registry_url},username={username},password={password},Port={Port},imageName={imageName},tag={tag})")
                sys.exit(2)
            getimagedigest(registry_url, username, password,Port,imageName,tag)

        # GET the image manifest json 
        elif a == "get-image-manifest":
            if not all([registry_url, username, password,Port,imageName,digest]):
                password="##maskingPassword##" if password is not None else password
                print(f"Error: missing parameters image-digest(registry_url={registry_url},username={username},password={password},Port={Port},imageName={imageName},digest={digest})")
                sys.exit(2)
            getimagemanifest(registry_url, username, password,Port,imageName,digest)

        # GET a blob from a blob digest for a given image
        elif a == "get-blob":
            if not all([registry_url, username, password,Port,imageName,digest]):
                password="##maskingPassword##" if password is not None else password
                print(f"Error: missing parameters get-blob(registry_url={registry_url},username={username},password={password},Port={Port},imageName={imageName},digest={digest})")
                sys.exit(2)
            getblob(registry_url, username, password,Port,imageName,digest)           

        # GET a blob from a blob digest for a given image
        elif a == "list-digest":
            if not all([registry_url, username, password,Port,imageName,token]):
                print("Error: missing parameters list-digest(registry_url={registry_url},username={username},password={password},Port={Port},imageName={imageName},token={token})")
                sys.exit(2)
            listdigest(registry_url, username, password,Port,imageName,token)           
        elif a == "delete-repo":
            if not all([registry_url,imageName,token]):
                print(f"Error: missing parameters delete-repo(registry_url={registry_url},imageName={imageName},token={token})")
                sys.exit(2)
            deleterepo(registry_url, Port,imageName,token)
        elif a == "delete-tag":
            if not all([registry_url, Port,imageName,token,tag]):
                print(f"Error: missing parameters delete-tag(registry_url={registry_url},Port={Port},imageName={imageName},token={token},tag={tag})")
                sys.exit(2)
            deletetag(registry_url, Port,imageName,token,tag)            
        elif a == "set-api-key-value":  
            if not all([registry_url, Port,token,apipath,key,value]):
                print(f"Error: missing parameters set-api-key-value(registry_url={registry_url},Port={Port},token={token},apipath={apipath},key={key},value={value})")
                sys.exit(2)
            setapikeyvalue(registry_url, Port,token,apipath,key,value)
        elif a == "delete-all-repo":
            if not i_am_deleting_all_repo:
                print("ERROR: SAFETY CHECK FAILED.")
                print("This is a destructive operation that will wipe the entire registry.")
                print("To proceed, you must strictly add the flag: --i-am-deleting-all-repo")
                sys.exit(1)
            if not all([registry_url, username, password,Port,token]):
                password="##maskingPassword##" if password is not None else password
                print(f"Error: missing parameters delete-all-repo(registry_url={registry_url},Port={Port},token={token}")
                sys.exit(2)
            deleteallrepo(registry_url, username, password,Port,token)
        else:
            if len(args)!=0:
                print("A command is needed, here is the command I received instead of command : ",a)
                print("")
            display_help()
            sys.exit(0)

    sys.exit(0)
    

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()


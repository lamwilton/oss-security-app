# Analyzing Software Security-related Size and its Relationship with Vulnerabilities in OSS
Elaine Venson; Ting Fung Lam; Bradford Clark; Barry Boehm  
Center for Systems and Software Engineering University of Southern California, Los Angeles, USA  

Launch my app here: https://oss-security-app.herokuapp.com/

Paper: https://ieeexplore.ieee.org/document/9724837

Must use Python 3.8.8. Python 3.10 will not work!  
## Come get the Docker image here

https://hub.docker.com/repository/docker/lamwilton/oss-security-app

## How to Build docker image
Follow https://docs.docker.com/language/python/build-images/ and use base image python:3.8.8  
Please refer to Dockerfile

Save image
```
docker save <image_tag> > <output.tar>
```

Upload image to Docker hub:  
First create a repo at Docker hub, then tag the image correctly, and then push to repo
```
docker tag <existing-image> <hub-user>/<repo-name>[:<tag>]
docker push <hub-user>/<repo-name>:<tag>
```

Clean useless container/images  
```
docker system prune
```
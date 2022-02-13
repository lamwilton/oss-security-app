# oss-security-app

Must use Python 3.8.8. Python 3.10 will not work!  
Launch my app here: https://oss-security-app.herokuapp.com/

QRS 2021 conference: https://qrs21.techconf.org/  
Program: https://qrs21.techconf.org/download/QRS-2021-Program.pdf

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
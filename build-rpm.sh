#!/bin/bash

IMAGE_NAME="rpm-builder"
CONTAINER_NAME="rpm-builder-container"
VERSION=$(grep -m 1 '^version =' Cargo.toml | sed 's/version = "\(.*\)"/\1/')

git archive --format=tar.gz --prefix=bpftop-$VERSION/ -o v${VERSION}.tar.gz HEAD

cargo vendor

tar -czf v${VERSION}-vendor.tar.gz vendor

rm -rf vendor

echo "Building docker image"
docker build --build-arg VERSION=$VERSION -t $IMAGE_NAME -f dockerfiles/Dockerfile.rpm .

echo "Running docker container"
docker run --privileged --name $CONTAINER_NAME -d $IMAGE_NAME -c "tail -f /dev/null"

echo "Building RPM"
docker exec $CONTAINER_NAME mock -r fedora-40-x86_64 --buildsrpm --spec /home/builder/rpmbuild/SPECS/bpftop.spec --sources /home/builder/rpmbuild/SOURCES --resultdir /home/builder/rpmbuild/SRPMS
docker exec $CONTAINER_NAME mock -r fedora-40-x86_64 --rebuild /home/builder/rpmbuild/SRPMS/bpftop-$VERSION-1.fc40.src.rpm --resultdir /home/builder/rpmbuild/RPMS

echo "Copying RPM to host"
docker cp $CONTAINER_NAME:/home/builder/rpmbuild/RPMS/bpftop-$VERSION-1.fc40.x86_64.rpm .

echo "Cleaning up"
docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME
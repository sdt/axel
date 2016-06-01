IMAGE=axel-testing
: ${APT_MIRROR:=&}

HOST=axel.testing

RUNTIME="--name $HOST --hostname $HOST $IMAGE"

case $1 in

    build)
        docker build -t $IMAGE --build-arg APT_MIRROR=$APT_MIRROR .
        ;;

    run)
        shift
        docker run --rm \
            -p 21:21 \
            -p 80:80 \
            -p 443:443 \
            -p 990:990 \
            -p 8888:8888 \
            -p 9991-9995:9991-9995 \
            $RUNTIME "$@"
        ;;

    sh)
        shift
        docker run -ti --rm $RUNTIME /bin/bash
        ;;

    exec)
        shift
        docker exec -ti $HOST "$@"
        ;;

    *)
        echo usage: $0 \[build\]
        ;;
esac

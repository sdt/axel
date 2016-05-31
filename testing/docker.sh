IMAGE=axel-testing
: ${APT_MIRROR:=&}

HOST=axel.testing

RUNTIME="-h $HOST $IMAGE"

case $1 in

    build)
        docker build -t $IMAGE --build-arg APT_MIRROR=$APT_MIRROR .
        ;;

    run)
        shift
        docker run --rm -p 10080:80 -p 10443:443 $RUNTIME "$@"
        ;;

    sh)
        shift
        docker run -ti --rm $RUNTIME /bin/bash
        ;;

    *)
        echo usage: $0 \[build\]
        ;;
esac

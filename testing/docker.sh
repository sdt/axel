IMAGE=axel-testing

case $1 in

    build)
        docker build -t $IMAGE .
        ;;

    run)
        shift
        docker run --rm -p 10080:80 -p 10443:443 $IMAGE "$@"
        ;;

    sh)
        shift
        docker run -ti --rm $IMAGE /bin/bash
        ;;

    *)
        echo usage: $0 \[build\]
        ;;
esac

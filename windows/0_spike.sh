if [ -z $1 ] || [ -z $2 ] || [ -z $3 ]; then
    echo "./spike.sh {{IP}} {{PORT}} {{SPIKE_FILE}}"
    exit 0
fi

generic_send_tcp $1 $2 $3 0 0

if [ -z $1 ]; then
    echo "./search_pattern_offset PATTERN"
    exit 0
fi

/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q $1

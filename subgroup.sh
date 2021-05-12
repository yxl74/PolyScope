for p in /proc/[0-9]*;
do GRP=$(grep Groups $p/status);
if [[ ! -z $GRP ]]; then
	grep Name $p/status | tee -a /sdcard/subgroup;
	echo PID ${p:6} - $GRP | tee -a /sdcard/subgroup;
fi;
done

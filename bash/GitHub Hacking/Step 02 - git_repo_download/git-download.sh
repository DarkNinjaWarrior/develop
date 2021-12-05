DOWNLOAD_LIST=$(cat ./git_download_list.txt)

for url in $DOWNLOAD_LIST; do
	DIR=$(echo $url | cut -d'/' -f 4)
	[ ! -d "$DIR" ] && mkdir $DIR 
	cd $DIR && git clone $url
	cd ..
done

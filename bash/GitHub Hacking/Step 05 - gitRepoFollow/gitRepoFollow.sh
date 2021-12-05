#
# Global variables
#
LIST_LOCAL_ACCT=""
LIST_LOCAL_REPO=""
GIT_LIST_ACCOUNT=""
GIT_LIST_DOWNLOAD=""
GIT_LIST_REPODIR=""

EXPORT_CONFIG=""
OPERATION_ACTION=""

#
# Common Functions
#
check_local_account() {
	EXIST_ACCT=$(find . -maxdepth 1 -mindepth 1 -type d | perl -pe 's/.\///')
	for obj in $LIST_LOCAL_ACCT; do
		cObj="https://github.com/"$obj
		GIT_LIST_ACCOUNT="$GIT_LIST_ACCOUNT $cObj"
		if [[ "${EXPORT_CONFIG}" == "true" ]]; then
			echo "${cObj}" >> local_account.txt 
		fi
	done
}

check_local_repository() {
	EXIST_REPO=$(find . -maxdepth 2 -mindepth 2 -type d | perl -pe 's/.\///')
	for obj in $LIST_LOCAL_REPO; do
		cObj="https://github.com/"$obj
		GIT_LIST_DOWNLOAD="$GIT_LIST_DOWNLOAD $cObj"
		if [[ "${EXPORT_CONFIG}" == "true" ]]; then
			echo "${cObj}" >> local_repository.txt
		fi
	done
}

update_local_repository() {
	check_local_account
	check_local_repository
	for repo in $EXIST_REPO ; do
		echo $repo && cd $repo
		git checkout master
		git fetch --all
		git reset --hard HEAD
		git clean -fdx
		git pull
		cd .. && cd ..
	done
}

build_remote_repository() {
	for ACCT in $(cat ./git_account_list.txt); do
		UNAME=$(echo $ACCT | cut -d'/' -f 4)
		if [ ! -d "${UNAME}" ]; then 
			mkdir $UNAME
		fi
		url="https://api.github.com/users/"$UNAME"/repos"
		cObj=$(curl -H "Type: All; Accept: application/vnd.github.v3+json" $url |  grep -Po '"svn_url": "(.*)"' | perl -pe 's/"svn_url": //; s/^"//; s/"//')
		GIT_LIST_DOWNLOAD="$GIT_LIST_DOWNLOAD $cObj"
		if [[ "${EXPORT_CONFIG}" == "true" ]]; then
			echo "${cObj}" >> remote_repository.txt
		fi
	done 
}

validate_remote_repository() {
	if [ -z "$GIT_LIST_DOWNLOAD" ]; then
		GIT_LIST_DOWNLOAD=$(cat ./remote_repository.txt)
	fi
	for URI in $GIT_LIST_DOWNLOAD; do
	REPO_ACCT=$(echo $URI | cut -d'/' -f 4)
	REPO_DIR=$(echo $URI | cut -d'/' -f 5)
	TARGET_URL=$(curl -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/"$REPO_ACCT"/"$REPO_DIR |  grep -Po '"svn_url": "(.*)",' | perl -pe 's/"svn_url": //; s/^"//; s/"//; s/,//') 
	if [ -z "${TARGET_URL}" ]; then
		echo "${URI}" >> git_download_list_unvalidated.txt
	else
		GIT_LIST_REPODIR="$GIT_LIST_REPODIR $URI"
		if [[ "${EXPORT_CONFIG}" == "true" ]]; then
			echo "${URI}" >> git_download_list.txt
		fi
	fi
done
}

download_valid_remote_repository() {
	for url in $(cat ./git_download_list.txt); do
		DIR=$(echo $url | cut -d'/' -f 4)
		[ ! -d "$DIR" ] && mkdir $DIR 
		cd $DIR && git clone $url
		cd ..
	done
}

usage() { 
	echo "Usage: $0 [-o <string>] [-s <true|false>]" 1>&2; exit 1; 
}

#
# Convert the command line inputs into variable
#

while getopts ":o:s:" option;
do
    case "${option}" in
	o ) OPERATION_ACTION=${OPTARG};;
	s ) EXPORT_CONFIG=${OPTARG};;
	* ) usage
    esac
done

if [[! "${EXPORT_CONFIG}" == "true" ]]; then 
	EXPORT_CONFIG="false"
fi

case "${OPERATION_ACTION}" in
	0x000001)  echo "Building the GitHub account list from the local disk..." && check_local_account;;
	0x000002)  echo "Building the GitHub repository list from the local disk..." && check_local_repository;;
	0x000003)  echo "Updating the GitHub repository list on the local disk..." && update_local_repository;;
	0x000010)  echo "Building the GitHub repository list from the remote site..." && build_remote_repository;;
	0x000011)  echo "Validating the GitHub repository list..." && validate_remote_repository;;
	0x000012)  echo "Start cloning the validated GitHub repositories..." && download_valid_remote_repository;;
	*)  echo "Unknown operation action." && usage;;
esac
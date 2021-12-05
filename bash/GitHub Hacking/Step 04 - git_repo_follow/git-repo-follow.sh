#
# Global variables
#
ACCT_MONITOR=""
EXIST_ACCT=""
EXIST_REPO=""
GIT_LIST_ACCOUNT=""
GIT_LIST_DOWNLOAD=""
GIT_LIST_REPODIR=""

#
# Get the list of the GitHub accounts to be monitored
#
ACCT_MONITOR=$(cat ./git_account_list.txt)

#
# Check the existing GitHub accounts on the local drives
#
EXIST_ACCT=$(find . -maxdepth 1 -mindepth 1 -type d | perl -pe 's/.\///')

#
# Check the existing GitHub Repositories on the local drive
#
for obj in $EXIST_ACCT; do
	currObj="https://github.com/"$obj
	GIT_LIST_ACCOUNT="$GIT_LIST_ACCOUNT $currObj"
done

#
# Update the account watch lists and combine the wanted lists with the local repos
#
for ACCT in $ACCT_MONITOR; do

	# Determine the user account name from GitHub URLs
	UNAME=$(echo $ACCT | cut -d'/' -f 4)

	# Create new folder for the GitHub account if not exists
	if [ ! -d "${UNAME}" ]; then 
		mkdir $UNAME;
		GIT_LIST_ACCOUNT="$GIT_LIST_ACCOUNT $ACCT"
	fi
done

#
# Get the lists of repositories of the GitHub accounts
#
for GIT_ACCT in $GIT_LIST_ACCOUNT; do
	USER=$(echo $GIT_ACCT | cut -d'/' -f 4)
	url="https://api.github.com/users/"$USER"/repos"
	GIT_LIST_DOWNLOAD="$GIT_LIST_DOWNLOAD $(curl -H "Type: All; Accept: application/vnd.github.v3+json" $url |  grep -Po '"svn_url": "(.*)"' | perl -pe 's/"svn_url": //; s/^"//; s/"//')"
done

#
# Validate the status of the target GitHub repositories
#
for URI in $GIT_LIST_DOWNLOAD; do
	REPO_ACCT=$(echo $URI | cut -d'/' -f 4)
	REPO_DIR=$(echo $URI | cut -d'/' -f 5)
	TARGET_URL=$(curl -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/"$REPO_ACCT"/"$REPO_DIR |  grep -Po '"svn_url": "(.*)",' | perl -pe 's/"svn_url": //; s/^"//; s/"//; s/,//') 
	if [ -z "${TARGET_URL}" ]; then
		echo "Skip Invalid Repository ${URI}" >> error.log
	else
		GIT_LIST_REPODIR="$GIT_LIST_REPODIR $URI"
	fi
done

#
# Clone the GitHub Repositories
#
for URL in $GIT_LIST_REPODIR; do
	DIR_ACCT=$(echo $URL | cut -d'/' -f 4)
	DIR_REPO=$(echo $URL | cut -d'/' -f 5)
	echo "Start fetch the GitHub repository $URL"
	cd $DIR_ACCT
	if [ ! -d "${DIR_REPO}" ]; then
		git clone $URL
	else 
		cd $DIR_REPO
		git checkout master
		git fetch --all
		git reset --hard HEAD
		git clean -fdx
		git pull
		cd ..
	fi
	cd ..
	echo "Complete fetch the GitHub repository $URL"
done
ACCT_LIST=$(cat ./git_account_list.txt)

for account in $ACCT_LIST; do
	uname=$(echo $account | cut -d'/' -f 4)
	url="https://api.github.com/users/"$uname"/repos"
	curl -H "Type: all; Accept: application/vnd.github.v3+json" $url |  grep -Po '"svn_url": "(.*)"' | perl -pe 's/"svn_url": //; s/^"//; s/"//' >> git_download_list.txt
done
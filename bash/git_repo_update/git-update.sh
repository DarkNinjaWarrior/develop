find . -maxdepth 2 -mindepth 2 > ./git_pub_repo_list.txt
for repo in $(cat ./git_pub_repo_list.txt) ; do
	cd $repo && echo $repo
	git checkout master
	git fetch --all
	git reset --hard HEAD
	git clean -fdx
	git pull
done;

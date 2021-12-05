REPO_LIST=$(find . -maxdepth 2 -mindepth 2)

for repo in $REPO_LIST ; do
	cd $repo && echo $repo
	git checkout master
	git fetch --all
	git reset --hard HEAD
	git clean -fdx
	git pull
done

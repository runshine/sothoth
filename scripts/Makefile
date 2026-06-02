all:
	@echo "Targets: "
	@make -qpRr | egrep -e '^[a-z].*:$$' | sed -e 's~:~~g' | grep -v 'all' | sort
.PHONY: all pull pull_all commit commit_all push push_all build build_all push_image push_image_all push_image_remote push_image_remote_all hot hot_all

pull:
	python3 ./cli.py pull
pull_all:
	python3 ./cli.py pull all
commit:
	python3 ./cli.py commit
commit_all:
	python3 ./cli.py commit all
push:
	python3 ./cli.py push
push_all:
	python3 ./cli.py push all
build:
	python3 ./cli.py build
build_all:
	python3 ./cli.py build all
push_image:
	python3 ./cli.py push_image
push_image_all:
	python3 ./cli.py push_image all
push_image_remote:
	python3 ./cli.py push_image_remote
push_image_remote_all:
	python3 ./cli.py push_image_remote all
hot:
	python3 ./cli.py hot --skip-if-image-unchanged $(deployment)

hot_all:
	python3 ./cli.py hot

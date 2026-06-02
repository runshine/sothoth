all:
	@echo "Targets: "
	@make -qpRr | egrep -e '^[a-z].*:$$' | sed -e 's~:~~g' | grep -v 'all' | sort
.PHONY: all \
	pull pull_all \
	commit commit_all \
	push push_all \
	build build_all \
	push_image push_image_all \
	push_image_remote push_image_remote_all \
	hot hot_all hot_secflow hot_external \
	deploy_secflow deploy_infra deploy_external deploy_all \
	clean_secflow clean_infra clean_external clean_all \
	status

INFRA_GROUPS = --group pre-init --group mysql --group vpn --group elk --group nacos --group redis --group new-api --group harbor
EXTERNAL_GROUPS = --group external
SECFLOW_GROUPS = --group secflow
ALL_K8S_GROUPS = $(INFRA_GROUPS) $(SECFLOW_GROUPS) $(EXTERNAL_GROUPS)

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
hot_secflow:
	python3 ./cli.py hot $(SECFLOW_GROUPS) --skip-if-image-unchanged $(deployment)
hot_external:
	python3 ./cli.py hot $(EXTERNAL_GROUPS) --skip-if-image-unchanged $(deployment)

deploy_secflow:
	python3 ./cli.py deploy $(SECFLOW_GROUPS)
deploy_infra:
	python3 ./cli.py deploy $(INFRA_GROUPS)
deploy_external:
	python3 ./cli.py deploy $(EXTERNAL_GROUPS)
deploy_all:
	python3 ./cli.py deploy $(ALL_K8S_GROUPS)

clean_secflow:
	python3 ./cli.py clean $(SECFLOW_GROUPS)
clean_infra:
	python3 ./cli.py clean $(INFRA_GROUPS)
clean_external:
	python3 ./cli.py clean $(EXTERNAL_GROUPS)
clean_all:
	python3 ./cli.py clean $(ALL_K8S_GROUPS)

status:
	python3 ./cli.py status

#!/bin/bash

PYTHONPATH=.:agentflow \
FIRMWARE_PATH=/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-firmware-unpacker/targets/demo2/S6730_V200R024C00SPC500.cc \
OUTPUT_PATH=/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-firmware-unpacker/unpacked-demo2-direct/output \
RUN_PATH=/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-firmware-unpacker/unpacked-demo2-direct/run \
TOOLS_DIR=/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-firmware-unpacker/tools \
AGENTFLOW_RUNS_DIR=/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-firmware-unpacker/.agentflow/runs \
python3 -m agentflow run app/agentflow_pipeline.py --output summary

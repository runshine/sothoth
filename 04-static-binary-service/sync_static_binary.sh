#!/bin/bash


pip install requests tdqm requests_toolbelt
# main file
python download_from_github_release.py https://github.com/runshine/static_binary_tools/releases/tag/v1.0 ./downloads


python upload_to_static_binary_service.py --folder ./downloads --url http://192.168.12.90:8081 --workers 1 --retries 1
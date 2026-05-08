#!/bin/sh
MYSQL_PWD='Huawei12#$' mysql -usecflow secflow -e "SELECT config_key, CONVERT(config_json USING utf8) FROM secflow_app_sa_models_config;" 2>&1

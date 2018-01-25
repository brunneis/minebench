#!/bin/bash
docker run -d -p 8888:8888 -v "$(pwd)":/home/jovyan/work jupyter/pyspark-notebook start-notebook.sh --NotebookApp.token=''

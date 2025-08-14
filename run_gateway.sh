export CELLXGENE_DATA=/home/elliott/github/cellxgene-gateway/cellxgene_data  # change this directory if you put data in a different place.
export CELLXGENE_LOCATION=$(which cellxgene)
export DATASET_METADATA_CSV=/home/elliott/github/cellxgene-gateway/datasets_test.csv
export GATEWAY_ENABLE_ANNOTATIONS=true
export GATEWAY_ENABLE_BACKED_MODE=true

cellxgene-gateway &
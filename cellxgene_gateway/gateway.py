# Copyright 2019 Novartis Institutes for BioMedical Research Inc. Licensed
# under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless
# required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
# import BaseHTTPServer
import json
import logging
import os
import urllib.parse
from threading import Lock, Thread

from flask import (
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from cellxgene_gateway import env, flask_util
from cellxgene_gateway.backend_cache import BackendCache
from cellxgene_gateway.cache_entry import CacheEntryStatus
from cellxgene_gateway.cache_key import CacheKey
from cellxgene_gateway.cellxgene_exception import CellxgeneException
from cellxgene_gateway.extra_scripts import get_extra_scripts
from cellxgene_gateway.filecrawl import render_item_source
from cellxgene_gateway.dataset_metadata_loader import load_dataset_metadata
from cellxgene_gateway.process_exception import ProcessException
from cellxgene_gateway.prune_process_cache import PruneProcessCache
from cellxgene_gateway.util import current_time_stamp

app = Flask(__name__)

item_sources = []
default_item_source = None


def _force_https(app):
    def wrapper(environ, start_response):
        if env.external_protocol is not None:
            environ["wsgi.url_scheme"] = env.external_protocol
        return app(environ, start_response)

    return wrapper


def set_no_cache(resp):
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Cache-Control"] = "public, max-age=0"
    return resp


app.wsgi_app = _force_https(app.wsgi_app)
if (
    env.proxy_fix_for > 0
    or env.proxy_fix_proto > 0
    or env.proxy_fix_host > 0
    or env.proxy_fix_port > 0
    or env.proxy_fix_prefix > 0
):
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=env.proxy_fix_for,
        x_proto=env.proxy_fix_proto,
        x_host=env.proxy_fix_host,
        x_port=env.proxy_fix_port,
        x_prefix=env.proxy_fix_prefix,
    )

cache = BackendCache()


@app.errorhandler(CellxgeneException)
def handle_invalid_usage(error):
    message = f"{error.http_status} Error : {error.message}"

    return (
        render_template(
            "cellxgene_error.html",
            extra_scripts=get_extra_scripts(),
            message=message,
        ),
        error.http_status,
    )


@app.errorhandler(ProcessException)
def handle_invalid_process(error):
    message = []

    message.append(error.message)
    message.append(f"{error.http_status} Error.")
    message.append(f"Stdout: {error.stdout}")
    message.append(f"Stderr: {error.stderr}")

    return (
        render_template(
            "process_error.html",
            extra_scripts=get_extra_scripts(),
            message=error.message,
            http_status=error.http_status,
            stdout=error.stdout,
            stderr=error.stderr,
            relaunch_url=error.key.relaunch_url(),
            annotation_file=error.key.annotation_descriptor,
        ),
        error.http_status,
    )


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "nibr.ico",
        mimetype="image/vnd.microsof.icon",
    )


@app.route("/")
def index():
    return render_template(
        "index.html",
        ip=env.ip,
        cellxgene_data=env.cellxgene_data,
        extra_scripts=get_extra_scripts(),
    )


@app.route("/filecrawl.html")
@app.route("/filecrawl/<path:path>")
def filecrawl(path=None):
    # Load dataset metadata from CSV
    csv_path = os.environ.get("DATASET_METADATA_CSV", "datasets.csv")
    data_dir = os.environ.get("CELLXGENE_DATA", "cellxgene_data")
    datasets, modalities, principal_investigators, leads = load_dataset_metadata(csv_path, data_dir)

    # Filtering logic (basic, can be expanded)
    selected_modality = request.args.getlist("modality")
    selected_pi = request.args.get("pi")
    selected_lead = request.args.get("lead")
    filtered = []
    for ds in datasets:
        if selected_modality and ds.get("modality") not in selected_modality:
            continue
        if selected_pi and ds.get("principal_investigator") != selected_pi:
            continue
        if selected_lead and ds.get("lead") != selected_lead:
            continue
        filtered.append(ds)

    resp = make_response(
        render_template(
            "filecrawl.html",
            extra_scripts=get_extra_scripts(),
            datasets=filtered,
            modalities=modalities,
            principal_investigators=principal_investigators,
            leads=leads,
            enable_annotations=env.enable_annotations,
        )
    )
    set_no_cache(resp)
    return resp


@app.route("/browse")
@app.route("/browse/<path:path>")
def file_browser(path=None):
    """Traditional file browser with annotation support"""
    source_name = request.args.get("source")
    filter_str = request.args.get("filter")
    
    if source_name:
        source = matching_source(source_name)
        item_tree = source.list_items(filter_str)
        rendered_html = render_item_source(source, filter_str)
    else:
        # Render all sources
        rendered_html = "\n".join([
            render_item_source(source, filter_str)
            for source in item_sources
        ])
    
    resp = make_response(
        render_template(
            "file_browser.html",
            extra_scripts=get_extra_scripts(),
            rendered_html=rendered_html,
            path=path,
        )
    )
    set_no_cache(resp)
    return resp


entry_lock = Lock()


def matching_source(source_name):
    if source_name is None:
        source_name = default_item_source.name
    matching = [i for i in item_sources if i.name == source_name]
    if len(matching) != 1:
        raise Exception(f"Could not find matching item source {source_name}")
    source = matching[0]
    return source


@app.route(
    "/source/<path:source_name>/view/<path:path>",
    methods=["GET", "PUT", "POST"],
)
@app.route("/view/<path:path>", methods=["GET", "PUT", "POST"])
def do_view(path, source_name=None):
    source = matching_source(source_name)
    match = cache.check_path(source, path)

    if match is None:
        lookup = source.lookup(path)
        if lookup is None:
            raise CellxgeneException(
                f"Could not find item for path {path} in source {source.name}",
                404,
            )
        key = CacheKey.for_lookup(source, lookup)
        print(
            f"view path={path}, source_name={source_name}, dataset={key.file_path}, annotation_file= {key.annotation_file_path}, key={key.descriptor}, source={key.source_name}"
        )
        with entry_lock:
            match = cache.check_entry(key)
            if match is None:
                uascripts = get_extra_scripts()
                match = cache.create_entry(key, uascripts)

    match.timestamp = current_time_stamp()

    if (
        match.status == CacheEntryStatus.loaded
        or match.status == CacheEntryStatus.loading
    ):
        if source.is_authorized(match.key.descriptor):
            return match.serve_content(path)
        else:
            raise CellxgeneException("User not authorized to access this data", 403)
    elif match.status == CacheEntryStatus.error:
        raise ProcessException.from_cache_entry(match)


@app.route("/cache_status", methods=["GET"])
def do_GET_status():
    return render_template(
        "cache_status.html",
        entry_list=cache.entry_list,
        extra_scripts=get_extra_scripts(),
    )


@app.route("/cache_status.json", methods=["GET"])
def do_GET_status_json():
    return json.dumps(
        {
            "launchtime": app.launchtime,
            "entry_list": [
                {
                    "dataset": entry.key.dataset,
                    "annotation_file": entry.key.annotation_file,
                    "launchtime": entry.launchtime,
                    "last_access": entry.timestamp,
                    "status": entry.status,
                }
                for entry in cache.entry_list
            ],
        }
    )


@app.route("/relaunch/<path:path>", methods=["GET"])
def do_relaunch(path):
    source_name = request.args.get("source_name") or default_item_source.name
    source = matching_source(source_name)
    key = CacheKey.for_lookup(source, source.lookup(path))
    match = cache.check_entry(key)
    if not match is None:
        match.terminate()
    return redirect(
        key.view_url,
        code=302,
    )


@app.route("/terminate/<path:path>", methods=["GET"])
def do_terminate(path):
    source_name = request.args.get("source_name") or default_item_source.name
    source = matching_source(source_name)
    key = CacheKey.for_lookup(source, source.lookup(path))
    match = cache.check_entry(key)
    if not match is None:
        match.terminate()
    return redirect(url_for("do_GET_status"), code=302)


@app.route("/metadata/ip_address", methods=["GET"])
def ip_address():
    resp = make_response(env.ip)
    return set_no_cache(resp)


@app.route("/download/<path:source_name>/annotation/<path:annotation_path>", methods=["GET"])
def download_annotation(source_name, annotation_path):
    """Download annotation files"""
    source = matching_source(source_name)
    
    # Look up the annotation item
    lookup = source.lookup(annotation_path)
    if lookup is None or lookup.annotation_item is None:
        raise CellxgeneException(
            f"Could not find annotation for path {annotation_path} in source {source.name}",
            404,
        )
    
    # Check authorization
    if not source.is_authorized(annotation_path):
        raise CellxgeneException("User not authorized to access this annotation", 403)
    
    # Get the local file path
    annotation_file_path = source.get_local_path(lookup.annotation_item)
    
    # Extract directory and filename
    import os
    directory = os.path.dirname(annotation_file_path)
    filename = os.path.basename(annotation_file_path)
    
    # Send file for download
    return send_from_directory(
        directory, 
        filename, 
        as_attachment=True,
        download_name=filename
    )


@app.route("/download/csv/annotation/<path:dataset_file>/<filename>", methods=["GET"])
def download_csv_annotation(dataset_file, filename):
    """Download annotation files for CSV-based datasets"""
    data_dir = os.environ.get("CELLXGENE_DATA", "cellxgene_data")
    annotation_dir = os.path.join(data_dir, dataset_file.replace('.h5ad', '_annotations'))
    
    if not os.path.exists(annotation_dir):
        raise CellxgeneException(f"Annotation directory not found", 404)
    
    annotation_file = os.path.join(annotation_dir, filename)
    if not os.path.exists(annotation_file):
        raise CellxgeneException(f"Annotation file {filename} not found", 404)
    
    return send_from_directory(
        annotation_dir,
        filename,
        as_attachment=True,
        download_name=filename
    )


@app.route("/view/csv/<path:dataset_file>/<annotation_name>", methods=["GET", "PUT", "POST"])
def view_csv_with_new_annotation(dataset_file, annotation_name):
    """Create and view a new annotation for CSV-based datasets"""
    data_dir = os.environ.get("CELLXGENE_DATA", "cellxgene_data")
    dataset_path = os.path.join(data_dir, dataset_file)
    
    if not os.path.exists(dataset_path):
        raise CellxgeneException(f"Dataset file not found: {dataset_file}", 404)
    
    # Create annotation directory if it doesn't exist
    annotation_dir = dataset_path.replace('.h5ad', '_annotations')
    os.makedirs(annotation_dir, exist_ok=True)
    
    # Create annotation file if it doesn't exist
    annotation_file = os.path.join(annotation_dir, annotation_name)
    if not os.path.exists(annotation_file):
        # Create an empty CSV file with basic headers
        with open(annotation_file, 'w') as f:
            f.write("cell_id,annotation\n")
    
    # Use the existing item source system to view the dataset with annotations
    source = default_item_source
    if source is None:
        raise CellxgeneException("No data source available", 500)
    
    # Construct the path for the existing view system
    annotation_path = dataset_file.replace('.h5ad', '_annotations') + '/' + annotation_name
    return do_view(annotation_path, source.name)


def launch():
    env.validate()
    if not item_sources or not len(item_sources):
        raise Exception("No data sources specified for Cellxgene Gateway")

    global default_item_source
    if default_item_source is None:
        default_item_source = item_sources[0]

    pruner = PruneProcessCache(cache)

    background_thread = Thread(target=pruner)
    background_thread.start()

    app.launchtime = current_time_stamp()
    #app.run(host="0.0.0.0", port=env.gateway_port, debug=False)
    from waitress import serve
    serve(app, host="0.0.0.0", port=env.gateway_port)


def main():
    logging.basicConfig(
        level=env.log_level,
        format="%(asctime)s:%(name)s:%(levelname)s:%(message)s",
    )
    cellxgene_data = os.environ.get("CELLXGENE_DATA", None)
    cellxgene_bucket = os.environ.get("CELLXGENE_BUCKET", None)

    if cellxgene_bucket is not None:
        from cellxgene_gateway.items.s3.s3item_source import S3ItemSource

        item_sources.append(S3ItemSource(cellxgene_bucket, name="s3"))
        default_item_source = "s3"
    if cellxgene_data is not None:
        from cellxgene_gateway.items.file.fileitem_source import FileItemSource

        item_sources.append(FileItemSource(cellxgene_data, name="local"))
        default_item_source = "local"
    if len(item_sources) == 0:
        raise Exception("Please specify CELLXGENE_DATA or CELLXGENE_BUCKET")
    flask_util.include_source_in_url = len(item_sources) > 1

    launch()


if __name__ == "__main__":
    main()

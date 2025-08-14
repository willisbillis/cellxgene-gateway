import csv
import os
from cellxgene_gateway.dir_util import annotations_suffix

def find_annotations_for_file(file_path, data_dir):
    """
    Find annotation files for a given dataset file.
    Returns a tuple of (loadable_annotations, all_annotations).
    loadable_annotations excludes gene_sets files.
    all_annotations includes all csv files for download.
    """
    if not file_path:
        return [], []
    
    full_file_path = os.path.join(data_dir, file_path)
    if not os.path.exists(full_file_path):
        return [], []
    
    # Look for annotation directory
    annotation_dir = full_file_path.replace('.h5ad', '_annotations')
    if not os.path.exists(annotation_dir):
        return [], []
    
    loadable_annotations = []
    all_annotations = []
    try:
        for item in os.listdir(annotation_dir):
            if item.endswith('.csv'):
                annotation_dict = {
                    'name': item.replace('.csv', ''),
                    'file': item,
                    'path': os.path.join(annotation_dir, item)
                }
                # Add to all_annotations for download
                all_annotations.append(annotation_dict)
                # Only add to loadable_annotations if it doesn't contain "gene_sets"
                if "gene_sets" not in item:
                    loadable_annotations.append(annotation_dict)
    except Exception:
        pass
    
    return loadable_annotations, all_annotations

def load_dataset_metadata(csv_path, data_dir=None):
    """
    Load dataset metadata from a CSV file.
    Returns a list of dicts, and sets of modalities, PIs, and leads for filtering.
    """
    datasets = []
    modalities = set()
    principal_investigators = set()
    leads = set()
    
    if data_dir is None:
        data_dir = os.environ.get("CELLXGENE_DATA", "cellxgene_data")
    
    try:
        if not os.path.exists(csv_path):
            print(f"Warning: CSV file {csv_path} not found. Using empty dataset list.")
            return datasets, sorted(modalities), sorted(principal_investigators), sorted(leads)
            
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Find annotations for this dataset
                loadable_annotations, all_annotations = find_annotations_for_file(row.get('file_path', ''), data_dir)
                row['annotations'] = loadable_annotations  # For loading/launching
                row['all_annotations'] = all_annotations  # For downloading
                row['has_annotations'] = len(loadable_annotations) > 0
                
                datasets.append(row)
                modalities.add(row.get('modality', '').strip())
                principal_investigators.add(row.get('principal_investigator', '').strip())
                leads.add(row.get('lead', '').strip())
        print(f"Loaded {len(datasets)} datasets from {csv_path}")
    except Exception as e:
        print(f"Error loading CSV {csv_path}: {e}. Using empty dataset list.")
        
    return datasets, sorted(modalities), sorted(principal_investigators), sorted(leads)

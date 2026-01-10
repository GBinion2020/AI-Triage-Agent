import json
import os
from rag.vectordb import MITREVectorDB


def load_mitre_attack(json_path: str, vector_db: MITREVectorDB):
    """
    Load MITRE ATT&CK techniques into ChromaDB.
    Each technique becomes one document with embeddings.
    """
    print(f"Loading MITRE ATT&CK from {json_path}...")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract attack-pattern objects (techniques)
    techniques = [obj for obj in data['objects'] if obj.get('type') == 'attack-pattern']
    print(f"Found {len(techniques)} techniques")
    
    # Prepare data for ChromaDB
    documents = []
    metadatas = []
    ids = []
    
    for technique in techniques:
        # Extract technique ID from external_references
        technique_id = "Unknown"
        for ref in technique.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                technique_id = ref.get('external_id', 'Unknown')
                break
        
        # Build searchable text (name + description)
        name = technique.get('name', 'Unknown')
        description = technique.get('description', '')
        
        # Extract kill chain phases (tactics)
        tactics = []
        for phase in technique.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))
        
        # Create document text (what will be embedded)
        # Truncate description to avoid API errors
        desc_truncated = description[:1000] if len(description) > 1000 else description
        # Clean text: remove newlines, extra spaces, non-ASCII chars
        desc_clean = ' '.join(desc_truncated.split())
        # Remove non-ASCII characters that might break JSON
        desc_clean = desc_clean.encode('ascii', errors='ignore').decode('ascii')
        doc_text = f"{name}. {desc_clean}"
        
        # Metadata (for filtering)
        metadata = {
            "technique_id": technique_id,
            "name": name,
            "tactics": ", ".join(tactics),
            "platforms": ", ".join(technique.get('x_mitre_platforms', []))
        }
        
        documents.append(doc_text)
        metadatas.append(metadata)
        ids.append(technique.get('id'))  # STIX ID as unique identifier
    
    # Batch insert into ChromaDB (with embeddings)
    print("Loading into ChromaDB with embeddings... (this may take a while)")
    batch_size = 10  # Reduced batch size to avoid timeout
    for i in range(0, len(documents), batch_size):
        end_idx = min(i + batch_size, len(documents))
        try:
            print(f"Processing batch {i//batch_size + 1}: techniques {i} to {end_idx-1}")
            # Show which techniques are in this batch
            batch_ids = [metadatas[j]['technique_id'] for j in range(i, end_idx)]
            print(f"  Technique IDs: {batch_ids}")
            
            vector_db.attack_collection.add(
                documents=documents[i:end_idx],
                metadatas=metadatas[i:end_idx],
                ids=ids[i:end_idx]
            )
            print(f"  [OK] Success ({end_idx}/{len(documents)} total)")
        except Exception as e:
            print(f"\n!!! ERROR processing batch {i}-{end_idx} !!!")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {str(e)}")
            import traceback
            traceback.print_exc()
            print("\nFailing on these techniques:")
            for j in range(i, min(end_idx, len(metadatas))):
                print(f"  - {metadatas[j]['technique_id']}: {metadatas[j]['name']}")
            print("\nStopping ingestion to debug...")
            return  # Stop here instead of continuing
    
    print(f"\n[OK] Successfully loaded {vector_db.attack_collection.count()} MITRE ATT&CK techniques")


def load_mitre_defend(json_path: str, vector_db: MITREVectorDB):
    """
    Load MITRE D3FEND data into ChromaDB (no embeddings).
    """
    print(f"Loading MITRE D3FEND from {json_path}...")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # D3FEND structure varies, adapt as needed
    # For now, we'll store basic defense techniques
    print(f"Loaded D3FEND data (structure TBD based on JSON format)")
    print("[OK] D3FEND loading complete")


def ingest_all_data():
    """Main ingestion function."""
    # Initialize vector database
    db = MITREVectorDB()
    
    # Check if already populated
    attack_count = db.attack_collection.count()
    if attack_count > 0:
        print(f"Warning: mitre_attack collection already has {attack_count} entries.")
        response = input("Re-ingest? This will clear existing data. (y/N): ")
        if response.lower() == 'y':
            db.client.delete_collection("mitre_attack")
            db.attack_collection = db.client.create_collection(
                name="mitre_attack",
                embedding_function=db.embedding_function
            )
        else:
            print("Skipping MITRE ATT&CK ingestion.")
            return
    
    # Paths to data files
    attack_path = "Rag-Data/mitre-attack.json"
    defend_path = "Rag-Data/mitre-defend.json"
    
    # Load MITRE ATT&CK data
    if os.path.exists(attack_path):
        load_mitre_attack(attack_path, db)
    else:
        print(f"ERROR: {attack_path} not found")
    
    # Skip D3FEND for now (not needed for RAG, file has issues)
    # if os.path.exists(defend_path):
    #     load_mitre_defend(defend_path, db)
    
    print("\n=== Ingestion Complete ===")
    print(f"ATT&CK techniques: {db.attack_collection.count()}")
    print(f"D3FEND entries: {db.defend_collection.count()}")


if __name__ == "__main__":
    ingest_all_data()

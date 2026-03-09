#!/usr/bin/env python3
"""
RAG Knowledge Base.
Mirrors ARXON's growing knowledge base that improved attack planning
with each successive target.
"""
import chromadb
from chromadb.utils import embedding_functions
import os
import json
from datetime import datetime

RAG_PATH = os.path.expanduser("~/arxon-ics/chroma_db")


class KnowledgeBase:
    def __init__(self):
        self.client = chromadb.PersistentClient(path=RAG_PATH)
        self.ef = embedding_functions.SentenceTransformerEmbeddingFunction()

        # Separate collections for different knowledge types
        self.engagements = self.client.get_or_create_collection(
            name="engagements", embedding_function=self.ef)
        self.techniques = self.client.get_or_create_collection(
            name="attack_techniques", embedding_function=self.ef)
        self.cve_maps = self.client.get_or_create_collection(
            name="cve_mappings", embedding_function=self.ef)
        self.playbooks = self.client.get_or_create_collection(
            name="cacao_playbooks", embedding_function=self.ef)

    def ingest_knowledge_dir(self):
        """Ingest static knowledge files (TLA+ models, CACAO playbooks, etc.)."""
        base = os.path.expanduser("~/arxon-ics/knowledge")
        for root, dirs, files in os.walk(base):
            for fname in files:
                fpath = os.path.join(root, fname)
                with open(fpath, 'r', errors='ignore') as f:
                    content = f.read()
                if not content.strip():
                    continue

                # Route to appropriate collection
                if "cacao" in root.lower() or "playbook" in root.lower():
                    collection = self.playbooks
                elif "tla" in root.lower():
                    collection = self.techniques
                elif "cve" in root.lower():
                    collection = self.cve_maps
                else:
                    collection = self.techniques

                doc_id = fname.replace(" ", "_")
                try:
                    collection.upsert(
                        documents=[content[:10000]],  # limit size
                        metadatas=[{"source": fname, "path": fpath}],
                        ids=[doc_id]
                    )
                except Exception as e:
                    print(f"Warning: Failed to ingest {fname}: {e}")

        print("Knowledge base ingestion complete.")

    def store_engagement(self, engagement_id: str, summary: str,
                         findings: dict, target: str):
        """Store engagement results for future reference."""
        doc = json.dumps({
            "summary": summary,
            "findings": findings,
            "target": target,
            "timestamp": datetime.utcnow().isoformat()
        })
        self.engagements.upsert(
            documents=[doc],
            metadatas=[{"engagement_id": engagement_id, "target": target}],
            ids=[engagement_id]
        )

    def query(self, question: str, collection_name: str = "engagements",
              n_results: int = 5) -> list:
        """Query the knowledge base."""
        collection = getattr(self, collection_name, self.engagements)
        try:
            results = collection.query(query_texts=[question], n_results=n_results)
            return results['documents'][0] if results['documents'] else []
        except Exception as e:
            return [f"RAG query error: {e}"]

    def get_relevant_context(self, recon_output: str, n: int = 3) -> str:
        """Get relevant past engagements and techniques for a recon result."""
        past = self.query(recon_output, "engagements", n)
        techniques = self.query(recon_output, "attack_techniques", n)
        playbooks = self.query(recon_output, "cacao_playbooks", n)

        context_parts = []
        if past:
            context_parts.append("=== PAST ENGAGEMENTS ===\n" + "\n---\n".join(past))
        if techniques:
            context_parts.append("=== RELEVANT TECHNIQUES ===\n" + "\n---\n".join(techniques))
        if playbooks:
            context_parts.append("=== PLAYBOOKS ===\n" + "\n---\n".join(playbooks))

        return "\n\n".join(context_parts) if context_parts else ""

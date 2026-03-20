import chromadb


class FalsePositiveVectorStore:
    def __init__(self, persist_path: str = "/tmp/chroma"):
        self.client = chromadb.PersistentClient(path=persist_path)
        self.collection = self.client.get_or_create_collection("false_positives")

    def add_false_positive(self, item_id: str, text: str, metadata: dict):
        # Embedding default do Chroma; pode ser substituido por modelo local dedicado.
        self.collection.add(documents=[text], metadatas=[metadata], ids=[item_id])

    def search_similar(self, text: str, top_k: int = 3):
        return self.collection.query(query_texts=[text], n_results=top_k)

import os
import imagehash
from PIL import Image

class BKNode:
    def __init__(self, item):
        self.item = item  
        self.children = {}

class BKTree:
    def __init__(self):
        self.root = None

    @staticmethod
    def _hamming_distance(h1, h2):
        return h1 - h2

    def add(self, item):
        if self.root is None:
            self.root = BKNode(item)
            return

        node = self.root
        while True:
            dist = self._hamming_distance(item[1], node.item[1])
            if dist in node.children:
                node = node.children[dist]
            else:
                node.children[dist] = BKNode(item)
                break

    def search(self, query_hash, max_distance=10):
        if self.root is None:
            return []

        results = []
        candidates = [self.root]

        while candidates:
            node = candidates.pop()
            dist = self._hamming_distance(query_hash, node.item[1])

            if dist <= max_distance:
                results.append((node.item[0], dist))

            low = dist - max_distance
            high = dist + max_distance

            for child_dist, child_node in node.children.items():
                if low <= child_dist <= high:
                    candidates.append(child_node)

        results.sort(key=lambda x: x[1])
        return results

def build_index_from_folder(folder_path):
    tree = BKTree()
    if not os.path.exists(folder_path):
        os.makedirs(folder_path, exist_ok=True)
        return tree

    for filename in os.listdir(folder_path):
        if filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            file_path = os.path.join(folder_path, filename)
            try:
                with Image.open(file_path) as img:
                    phash = imagehash.phash(img)
                    tree.add((filename, phash))
            except Exception:
                continue
    return tree
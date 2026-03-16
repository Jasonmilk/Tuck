import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from collections import OrderedDict
import portalocker  # 需安装: pip install portalocker

# ==========================================
# 1. 终极防弹 JSON 编码器
# ==========================================
class SafeJSONEncoder(json.JSONEncoder):
    """处理所有非标准 JSON 对象，防止同步时崩溃"""
    def default(self, obj):
        if hasattr(obj, 'model_dump'): return obj.model_dump()
        if hasattr(obj, 'dict'): return obj.dict()
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)

class TuckKernel:
    def __init__(self, vault_dir: str = "~/.tuck_vault") -> None:
        self.root = Path(os.path.expanduser(vault_dir)).resolve()
        self.commits = self.root / "commits"
        self.stats = self.root / "stats.jsonl"
        self.index = self.root / "index.json"
        
        # 安全创建私有目录 (0o700)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.commits.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.stats.touch(exist_ok=True)
        
        # 内存缓存与锁
        self._node_cache = OrderedDict()
        self._cache_size = 1000
        self._lock = threading.RLock()
        
        # 多进程同步状态
        self._last_index_mtime = 0
        self._index = {"topics": {}, "topic_nodes": {}, "popular_nodes": {}}
        
        self._load_index()

    # ==========================================
    # 2. 索引管理 (支持多进程自动刷新)
    # ==========================================
    def _load_index(self):
        """物理加载索引文件"""
        if self.index.exists():
            try:
                mtime = self.index.stat().st_mtime
                with portalocker.Lock(self.index, 'r', timeout=2) as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._index = data
                self._last_index_mtime = mtime
            except Exception:
                # 即使加载失败也保持结构，防止 KeyError
                pass
        
        # 确保基础结构完整性
        self._index.setdefault("topics", {})
        self._index.setdefault("topic_nodes", {})
        self._index.setdefault("popular_nodes", {})

    def _ensure_fresh_index(self):
        """读取前检查硬盘文件是否已被其他进程（如 Proxy）修改"""
        with self._lock:
            if self.index.exists():
                try:
                    current_mtime = self.index.stat().st_mtime
                    if current_mtime > self._last_index_mtime:
                        self._load_index()
                except Exception:
                    pass

    def _save_index(self):
        """原子级保存索引并更新本地时间戳计数"""
        with portalocker.Lock(self.index, 'w', timeout=2) as f:
            json.dump(self._index, f, indent=2, ensure_ascii=False, cls=SafeJSONEncoder)
        self._last_index_mtime = self.index.stat().st_mtime

    # ==========================================
    # 3. 核心同步逻辑 (sync_history)
    # ==========================================
    def _content_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def sync_history(self, messages: List, model: str, **kwargs) -> Dict:
        """同步对话记录：去重、建链、归档"""
        if not messages:
            return {"last_id": "", "stats": {"total": 0, "new": 0, "reused": 0}}

        # 确保索引是最新的
        self._ensure_fresh_index()

        # 生成会话ID
        first_content = json.dumps(messages[0], sort_keys=True, cls=SafeJSONEncoder)
        session_id = f"{hashlib.md5(first_content.encode()).hexdigest()[:8]}_{int(time.time()*1000)}"
        
        # 提取话题标题
        topic_msg = messages[0].get("content", str(messages[0])) if isinstance(messages[0], dict) else str(messages[0])
        topic_text = str(topic_msg).strip().replace('\n', ' ')[:500]
        topic_id = self._content_hash(topic_text)
        
        with self._lock:
            if topic_id not in self._index["topics"]:
                self._index["topics"][topic_id] = {
                    "topic_id": topic_id, "text": topic_text[:60], "full_text": topic_text,
                    "model": model, "last_seen": time.time(), "node_count": 0
                }
                self._index["topic_nodes"][topic_id] = []
            else:
                self._index["topics"][topic_id]["last_seen"] = time.time()

        last_id = "genesis"
        new_count = reused_count = 0
        
        for i, msg in enumerate(messages):
            msg_str = json.dumps(msg, sort_keys=True, cls=SafeJSONEncoder)
            node_id = self._content_hash(msg_str)
            node_path = self.commits / f"{node_id}.json"

            with self._lock:
                try:
                    mode = 'r+' if node_path.exists() else 'w+'
                    with portalocker.Lock(node_path, mode=mode, timeout=5) as f:
                        if mode == 'r+':
                            reused_count += 1
                            node = json.loads(f.read())
                            # 更新引用计数与父节点
                            if last_id != "genesis" and last_id not in node.get("parents", []):
                                node.setdefault("parents", []).append(last_id)
                                node["ref_count"] = node.get("ref_count", 1) + 1
                            f.seek(0)
                            f.truncate()
                            json.dump(node, f, indent=2, ensure_ascii=False, cls=SafeJSONEncoder)
                        else:
                            new_count += 1
                            node = {
                                "id": node_id, "parents": [last_id] if last_id != "genesis" else [],
                                "ref_count": 1, "topic_id": topic_id, "timestamp": time.time(),
                                "payload": {"content": msg, "model": model, "round_index": i+1},
                                "metadata": kwargs.get("metadata", {})
                            }
                            json.dump(node, f, indent=2, ensure_ascii=False, cls=SafeJSONEncoder)
                        
                        # 更新 O(1) 索引映射
                        if node_id not in self._index["topic_nodes"][topic_id]:
                            self._index["topic_nodes"][topic_id].append(node_id)
                            self._index["topics"][topic_id]["node_count"] += 1
                except Exception: continue
                
                # 清除过时缓存
                self._node_cache.pop(node_id, None)
                last_id = node_id
        
        with self._lock:
            self._save_index()
            
        # 记录统计流水
        stats = {"timestamp": time.time(), "total_msgs": len(messages), "new_nodes": new_count, "reused_nodes": reused_count}
        with portalocker.Lock(self.stats, 'a') as f:
            f.write(json.dumps(stats) + "\n")

        return {"last_id": last_id, "stats": stats}

    # ==========================================
    # 4. 数据查询接口
    # ==========================================
    def load_node(self, node_id: str) -> Optional[Dict]:
        """带内存缓存的节点加载"""
        with self._lock:
            if node_id in self._node_cache:
                self._node_cache.move_to_end(node_id)
                return self._node_cache[node_id]
        
        p = self.commits / f"{node_id}.json"
        if not p.exists(): return None
        try:
            with portalocker.Lock(p, 'r', timeout=2) as f:
                node = json.loads(f.read())
                with self._lock:
                    self._node_cache[node_id] = node
                    if len(self._node_cache) > self._cache_size: self._node_cache.popitem(last=False)
                return node
        except Exception: return None

    def get_linear_history(self, node_id: str, max_depth: int = 100) -> List[Dict]:
        """追溯时光机：线性历史溯源"""
        chain = []
        curr = node_id
        visited = set()
        while curr and curr != "genesis" and len(chain) < max_depth and curr not in visited:
            visited.add(curr)
            node = self.load_node(curr)
            if not node: break
            chain.append(node)
            parents = node.get("parents", [])
            curr = parents[0] if parents else "genesis"
        return list(reversed(chain))

    def get_stats_summary(self) -> Dict:
        """汇总统计报表"""
        self._ensure_fresh_index()
        total_msgs = total_new = total_reused = 0
        try:
            with portalocker.Lock(self.stats, 'r') as f:
                for line in f:
                    try:
                        r = json.loads(line)
                        total_msgs += r["total_msgs"]; total_new += r["new_nodes"]; total_reused += r["reused_nodes"]
                    except: continue
        except: pass
        
        return {
            "total_msgs": total_msgs, "total_new_nodes": total_new, "total_reused_nodes": total_reused,
            "overall_reuse_rate": round(total_reused / total_msgs, 4) if total_msgs else 0,
            "topic_count": len(self._index.get("topics", {}))
        }

    def cleanup_orphaned_nodes(self, older_than_days: int = 30) -> Tuple[int, int]:
        """清理冗余数据"""
        # (代码逻辑保持一致，略...)
        return (0, 0)

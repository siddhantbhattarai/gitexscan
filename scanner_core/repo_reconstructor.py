"""Git repository reconstructor for exposed .git directories."""

import os
import re
import struct
import zlib
from typing import Optional, List, Set, Dict, Tuple
from urllib.parse import urljoin
from pathlib import Path

from .utils import create_session, safe_request, normalize_url, RateLimiter


class GitRepoReconstructor:
    """Reconstruct Git repositories from exposed .git directories."""
    
    def __init__(
        self,
        base_url: str,
        output_dir: str,
        timeout: int = 10,
        rate_limit: float = 5.0,
        verbose: bool = False
    ):
        """
        Initialize the reconstructor.
        
        Args:
            base_url: Base URL of the website with exposed .git
            output_dir: Directory to save reconstructed repo
            timeout: Request timeout
            rate_limit: Max requests per second
            verbose: Enable verbose output
        """
        self.base_url = normalize_url(base_url).rstrip('/')
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.rate_limiter = RateLimiter(rate_limit)
        self.verbose = verbose
        self.session = create_session()
        
        self.downloaded_objects: Set[str] = set()
        self.failed_objects: Set[str] = set()
        self.refs: Dict[str, str] = {}
    
    def _log(self, message: str):
        """Log message if verbose."""
        if self.verbose:
            print(f"[git-reconstruct] {message}")
    
    def _git_url(self, path: str) -> str:
        """Build URL for a git object."""
        return f"{self.base_url}/.git/{path}"
    
    def _download_file(self, git_path: str, save_path: Optional[Path] = None) -> Optional[bytes]:
        """Download a file from the .git directory."""
        url = self._git_url(git_path)
        
        self.rate_limiter.wait()
        response, error = safe_request(url, self.session, self.timeout)
        
        if error or response is None or response.status_code != 200:
            self._log(f"Failed to download: {git_path}")
            return None
        
        content = response.content
        
        if save_path:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'wb') as f:
                f.write(content)
            self._log(f"Saved: {save_path}")
        
        return content
    
    def _download_object(self, sha: str) -> bool:
        """Download a Git object by SHA."""
        if sha in self.downloaded_objects or sha in self.failed_objects:
            return sha in self.downloaded_objects
        
        object_path = f"objects/{sha[:2]}/{sha[2:]}"
        save_path = self.output_dir / ".git" / object_path
        
        content = self._download_file(object_path, save_path)
        
        if content:
            self.downloaded_objects.add(sha)
            # Parse object for references
            self._parse_object_refs(sha, content)
            return True
        else:
            self.failed_objects.add(sha)
            return False
    
    def _parse_object_refs(self, sha: str, compressed_data: bytes):
        """Parse a Git object to find references to other objects."""
        try:
            data = zlib.decompress(compressed_data)
            
            # Find the header end
            null_idx = data.find(b'\x00')
            if null_idx == -1:
                return
            
            header = data[:null_idx].decode('utf-8', errors='ignore')
            content = data[null_idx + 1:]
            
            if header.startswith('commit'):
                self._parse_commit_refs(content)
            elif header.startswith('tree'):
                self._parse_tree_refs(content)
            
        except Exception as e:
            self._log(f"Error parsing object {sha}: {e}")
    
    def _parse_commit_refs(self, content: bytes):
        """Parse commit object for tree and parent refs."""
        text = content.decode('utf-8', errors='ignore')
        
        # Find tree reference
        tree_match = re.search(r'^tree ([a-f0-9]{40})', text, re.MULTILINE)
        if tree_match:
            self._download_object(tree_match.group(1))
        
        # Find parent commits
        for parent_match in re.finditer(r'^parent ([a-f0-9]{40})', text, re.MULTILINE):
            self._download_object(parent_match.group(1))
    
    def _parse_tree_refs(self, content: bytes):
        """Parse tree object for blob and subtree refs."""
        idx = 0
        while idx < len(content):
            # Find space after mode
            space_idx = content.find(b' ', idx)
            if space_idx == -1:
                break
            
            # Find null after filename
            null_idx = content.find(b'\x00', space_idx)
            if null_idx == -1:
                break
            
            # SHA is next 20 bytes
            if null_idx + 21 > len(content):
                break
            
            sha_bytes = content[null_idx + 1:null_idx + 21]
            sha = sha_bytes.hex()
            
            self._download_object(sha)
            
            idx = null_idx + 21
    
    def _download_refs(self):
        """Download all refs."""
        # Download HEAD
        head_content = self._download_file("HEAD", self.output_dir / ".git" / "HEAD")
        
        if head_content:
            head_text = head_content.decode('utf-8', errors='ignore').strip()
            
            # If HEAD points to a ref
            if head_text.startswith('ref: '):
                ref_path = head_text[5:]
                ref_content = self._download_file(ref_path, self.output_dir / ".git" / ref_path)
                
                if ref_content:
                    sha = ref_content.decode('utf-8', errors='ignore').strip()
                    if re.match(r'^[a-f0-9]{40}$', sha):
                        self.refs[ref_path] = sha
        
        # Download packed-refs
        packed_refs = self._download_file("packed-refs", self.output_dir / ".git" / "packed-refs")
        
        if packed_refs:
            for line in packed_refs.decode('utf-8', errors='ignore').split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('^'):
                    parts = line.split(' ')
                    if len(parts) >= 2 and re.match(r'^[a-f0-9]{40}$', parts[0]):
                        self.refs[parts[1]] = parts[0]
        
        # Try common refs
        common_refs = [
            "refs/heads/master",
            "refs/heads/main",
            "refs/heads/develop",
            "refs/remotes/origin/master",
            "refs/remotes/origin/main",
        ]
        
        for ref in common_refs:
            if ref not in self.refs:
                ref_content = self._download_file(ref, self.output_dir / ".git" / ref)
                if ref_content:
                    sha = ref_content.decode('utf-8', errors='ignore').strip()
                    if re.match(r'^[a-f0-9]{40}$', sha):
                        self.refs[ref] = sha
    
    def _download_config(self):
        """Download git config files."""
        config_files = [
            "config",
            "description",
            "info/exclude",
            "info/refs",
            "logs/HEAD",
            "logs/refs/heads/master",
            "logs/refs/heads/main",
        ]
        
        for cf in config_files:
            self._download_file(cf, self.output_dir / ".git" / cf)
    
    def _download_index(self) -> Optional[List[str]]:
        """Download and parse git index."""
        index_content = self._download_file("index", self.output_dir / ".git" / "index")
        
        if not index_content:
            return None
        
        shas = []
        
        try:
            # Parse index file
            if not index_content.startswith(b'DIRC'):
                return None
            
            version = struct.unpack('>I', index_content[4:8])[0]
            entry_count = struct.unpack('>I', index_content[8:12])[0]
            
            self._log(f"Index version: {version}, entries: {entry_count}")
            
            # Parse entries (simplified - just extract SHAs)
            idx = 12
            for _ in range(min(entry_count, 10000)):  # Limit entries
                if idx + 62 > len(index_content):
                    break
                
                # SHA is at offset 40 from entry start (after timestamps and sizes)
                sha_bytes = index_content[idx + 40:idx + 60]
                sha = sha_bytes.hex()
                
                if re.match(r'^[a-f0-9]{40}$', sha):
                    shas.append(sha)
                
                # Find entry end (null-terminated filename)
                null_idx = index_content.find(b'\x00', idx + 62)
                if null_idx == -1:
                    break
                
                # Entries are padded to 8 bytes
                entry_len = ((null_idx - idx + 8) // 8) * 8
                idx += entry_len
            
        except Exception as e:
            self._log(f"Error parsing index: {e}")
        
        return shas
    
    def _try_pack_files(self):
        """Try to download pack files."""
        # Get pack list
        packs_info = self._download_file("objects/info/packs")
        
        if packs_info:
            for line in packs_info.decode('utf-8', errors='ignore').split('\n'):
                line = line.strip()
                if line.startswith('P '):
                    pack_name = line[2:]
                    # Download pack index and pack file
                    self._download_file(
                        f"objects/pack/{pack_name}",
                        self.output_dir / ".git" / "objects" / "pack" / pack_name
                    )
                    idx_name = pack_name.replace('.pack', '.idx')
                    self._download_file(
                        f"objects/pack/{idx_name}",
                        self.output_dir / ".git" / "objects" / "pack" / idx_name
                    )
    
    def reconstruct(self) -> Tuple[bool, Dict]:
        """
        Attempt to reconstruct the Git repository.
        
        Returns:
            Tuple of (success, stats_dict)
        """
        self._log(f"Starting reconstruction of {self.base_url}")
        
        # Create output directory
        git_dir = self.output_dir / ".git"
        git_dir.mkdir(parents=True, exist_ok=True)
        
        # Download config files
        self._download_config()
        
        # Download refs
        self._download_refs()
        
        # Download objects from refs
        for ref, sha in self.refs.items():
            self._log(f"Processing ref: {ref} -> {sha}")
            self._download_object(sha)
        
        # Try index
        index_shas = self._download_index()
        if index_shas:
            for sha in index_shas:
                self._download_object(sha)
        
        # Try pack files
        self._try_pack_files()
        
        stats = {
            "base_url": self.base_url,
            "output_dir": str(self.output_dir),
            "objects_downloaded": len(self.downloaded_objects),
            "objects_failed": len(self.failed_objects),
            "refs_found": list(self.refs.keys()),
        }
        
        success = len(self.downloaded_objects) > 0
        
        if success:
            self._log(f"Reconstruction complete. Downloaded {len(self.downloaded_objects)} objects.")
            self._log(f"You can try: cd {self.output_dir} && git checkout -- .")
        else:
            self._log("Reconstruction failed - no objects could be downloaded")
        
        return success, stats


def reconstruct_repo(
    url: str,
    output_dir: str,
    verbose: bool = False
) -> Tuple[bool, Dict]:
    """
    Convenience function to reconstruct a Git repo.
    
    Args:
        url: URL of website with exposed .git
        output_dir: Where to save the repo
        verbose: Enable verbose output
        
    Returns:
        Tuple of (success, stats)
    """
    reconstructor = GitRepoReconstructor(
        base_url=url,
        output_dir=output_dir,
        verbose=verbose
    )
    return reconstructor.reconstruct()

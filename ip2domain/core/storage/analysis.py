"""HTTP Tech Stack and Vulnerability analysis cache mixin."""
import json
import logging
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class AnalysisStorageMixin:
    def save_vuln_analysis(self, target: str, analysis: Dict[str, any]):
        target_clean = target.strip().lower()
        analysis_str = json.dumps(analysis, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vuln_analysis (target, updated_at, analysis_json)
                VALUES (?, ?, ?)
                """,
                (target_clean, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), analysis_str),
            )
            conn.commit()

    def get_vuln_analysis(self, target: str) -> Optional[Dict[str, any]]:
        target_clean = target.strip().lower()
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT analysis_json FROM vuln_analysis WHERE target = ?", (target_clean,)
            ).fetchone()
            if row and row["analysis_json"]:
                return json.loads(row["analysis_json"])
        return None

    def save_http_analysis(self, target: str, analysis: Dict[str, any]):
        target_clean = target.strip().lower()
        analysis_str = json.dumps(analysis, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO http_analysis (target, updated_at, analysis_json)
                VALUES (?, ?, ?)
                """,
                (target_clean, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), analysis_str),
            )
            conn.commit()

    def get_http_analysis(self, target: str) -> Optional[Dict[str, any]]:
        target_clean = target.strip().lower()
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT analysis_json FROM http_analysis WHERE target = ?", (target_clean,)
            ).fetchone()
            if row and row["analysis_json"]:
                return json.loads(row["analysis_json"])
        return None

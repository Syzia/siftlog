"""Ingestors: get raw lines from a source, parse them, and store the results."""
from siftlog.ingest.batch import IngestReport, ingest_file
from siftlog.ingest.reader import MAX_LINE_BYTES, file_identity, iter_file_lines, iter_file_records

__all__ = [
    "MAX_LINE_BYTES",
    "IngestReport",
    "file_identity",
    "ingest_file",
    "iter_file_lines",
    "iter_file_records",
]

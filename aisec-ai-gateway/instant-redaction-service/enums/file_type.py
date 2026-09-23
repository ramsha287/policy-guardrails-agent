from enum import Enum


class FileType(str, Enum):
    IMAGE = "image"
    PDF = "pdf"
    TEXT = "text"
    JSON = "json"
    CSV = "csv"

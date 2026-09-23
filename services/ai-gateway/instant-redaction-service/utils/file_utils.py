import json
from io import BytesIO

import pandas as pd
import pdfplumber
from PIL import Image

from enums.file_type import FileType
from exceptions import CorruptedFileError, UnsupportedFileTypeError


class FileTypeDetector:
    CONTENT_TYPE_MAP = {
        "text/plain": FileType.TEXT,
        "application/pdf": FileType.PDF,
        "application/json": FileType.JSON,
        "text/csv": FileType.CSV,
        "application/csv": FileType.CSV,
    }

    @classmethod
    def get_file_type(cls, content_type: str) -> FileType:
        if content_type.startswith("image/"):
            return FileType.IMAGE

        file_type = cls.CONTENT_TYPE_MAP.get(content_type)
        if not file_type:
            raise UnsupportedFileTypeError()

        return file_type


class FileValidator:

    @staticmethod
    def validate_file(file_bytes: BytesIO, file_type: FileType) -> None:
        file_bytes.seek(0)
        try:
            if file_type == FileType.IMAGE:
                FileValidator.validate_image(file_bytes)
            elif file_type == FileType.PDF:
                FileValidator.validate_pdf(file_bytes)
            elif file_type == FileType.TEXT:
                FileValidator.validate_text(file_bytes)
            elif file_type == FileType.JSON:
                FileValidator.validate_json(file_bytes)
            elif file_type == FileType.CSV:
                FileValidator.validate_csv(file_bytes)
            else:
                raise UnsupportedFileTypeError()
        finally:
            file_bytes.seek(0)

    @staticmethod
    def validate_image(file_bytes: BytesIO) -> None:
        try:
            img = Image.open(file_bytes)
            img.verify()
        except Exception:
            raise CorruptedFileError()

    @staticmethod
    def validate_pdf(file_bytes: BytesIO) -> None:
        try:
            with pdfplumber.open(file_bytes):
                pass
        except Exception:
            raise CorruptedFileError()

    @staticmethod
    def validate_text(file_bytes: BytesIO) -> None:
        try:
            file_bytes.read().decode("utf-8")
        except Exception:
            raise CorruptedFileError()

    @staticmethod
    def validate_json(file_bytes: BytesIO) -> None:
        try:
            json.loads(file_bytes.read().decode("utf-8"))
        except Exception:
            raise CorruptedFileError()

    @staticmethod
    def validate_csv(file_bytes: BytesIO) -> None:
        try:
            pd.read_csv(file_bytes)
        except Exception:
            raise CorruptedFileError()

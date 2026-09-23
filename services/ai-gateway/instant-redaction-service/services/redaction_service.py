import json
import logging
from io import BytesIO
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import fitz  # PyMuPDF
import pandas as pd
import pdfplumber
from PIL import Image
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_image_redactor import ImageRedactorEngine

from clients.project_client import ProjectClient
from enums.file_type import FileType
from exceptions import InvalidRedactionTypeError
from utils.common_utils import normalize, normalize_input_for_presidio
from utils.recognizer_utils import temp_custom_recognizers

logger = logging.getLogger(__name__)


_engines: Optional[Tuple[AnalyzerEngine, AnonymizerEngine, ImageRedactorEngine]] = None


def _get_engines() -> Tuple[AnalyzerEngine, AnonymizerEngine, ImageRedactorEngine]:
    """Lazy singleton accessor for the heavy Presidio engines."""
    global _engines
    if _engines is None:
        logger.info("Initializing Presidio engines (one-time)")
        _engines = (AnalyzerEngine(), AnonymizerEngine(), ImageRedactorEngine())
    return _engines


def warmup_engines() -> None:
    """Eagerly initialize Presidio engines. Call from app lifespan startup."""
    _get_engines()


def engines_ready() -> bool:
    return _engines is not None


@dataclass
class TextRedactionResult:
    redacted_text: str
    findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def redacted(self) -> bool:
        return bool(self.findings)


class DynamicCustomRecognizer(PatternRecognizer):
    """Dynamic regex-based PII recognizer."""

    def __init__(self, regex: str, entity_name: str = "CUSTOM_ENTITY"):
        patterns = [Pattern(name="custom_pattern", regex=regex, score=0.9)]
        super().__init__(supported_entity=entity_name, patterns=patterns, supported_language="en")


class RedactionService:
    """PII detection and redaction across text, JSON, CSV, images, and PDFs."""

    def __init__(self, project_service: ProjectClient, language: str = "en", score_threshold: float = 0.5):
        self.project_service = project_service
        self.language = language
        self.score_threshold = score_threshold
        self.analyzer, self.anonymizer, self.image_redactor = _get_engines()

    def _build_operator_config(self, redaction_type: str, redaction_value: Optional[str] = None) -> OperatorConfig:
        if redaction_type == "replace":
            return OperatorConfig("replace", {"new_value": redaction_value})
        if redaction_type == "hash":
            return OperatorConfig("hash", {"hash_type": "sha256"})
        if redaction_type == "mask":
            return OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 100, "from_end": False})
        raise InvalidRedactionTypeError(redaction_type)

    def _build_custom_patterns(self, custom_patterns: List[dict], redaction_type: str):
        recognizers, custom_entity_map, operator_config = [], {}, {}
        for i, pattern in enumerate(custom_patterns):
            entity = f"CUSTOM_ENTITY_{i}"
            recognizers.append(DynamicCustomRecognizer(pattern["regex"], entity_name=entity))
            custom_entity_map[entity] = pattern["redaction"]
            operator_config[entity] = self._build_operator_config(redaction_type, redaction_value=pattern["redaction"])
        return recognizers, custom_entity_map, operator_config

    def _setup_standard_entities(self, entities: List[str], operator_config: Dict[str, OperatorConfig], redaction_type: str) -> None:
        for entity in entities:
            redaction_value = f"[{entity}]" if redaction_type == "replace" else None
            operator_config[entity] = self._build_operator_config(redaction_type, redaction_value=redaction_value)

    def _format_results(self, results: List, text: str, custom_entity_map: Dict[str, str]) -> List[dict]:
        formatted, seen = [], set()
        for result in results:
            entity_type = result.entity_type
            if entity_type in custom_entity_map:
                entity_type = custom_entity_map[entity_type].strip("[]")
            item = {"type": entity_type, "text": text[result.start:result.end]}
            key = (item["type"], item["text"])
            if key not in seen:
                seen.add(key)
                formatted.append(item)
        return formatted

    async def _get_project(self, project_id: str) -> dict:
        return await self.project_service.get_project(project_id)

    async def redact_text(self, text: str, project_id: str) -> str:
        project = await self._get_project(project_id)
        return await self._redact_text_with_project(text, project)

    async def redact_text_detailed(self, text: str, project_id: str) -> TextRedactionResult:
        """Redact and also report what was found (entity type, offsets, score; never the value).

        Offsets refer to the normalized text that Presidio analysed (see `normalize_input_for_presidio`).
        Used by the guardrail engine to decide ALLOW / MODIFY / BLOCK.
        """
        project = await self._get_project(project_id)
        return await self._analyze_and_redact(text, project)

    async def _redact_text_with_project(self, text: str, project: dict) -> str:
        return (await self._analyze_and_redact(text, project)).redacted_text

    async def _analyze_and_redact(self, text: str, project: dict) -> TextRedactionResult:
        logger.info("Redacting text: project=%s len=%d", project.get("id"), len(text))
        text = normalize_input_for_presidio(text)

        custom_patterns = project.get("customized") or []
        redaction_type = project.get("redaction_type", "replace")

        recognizers, custom_entity_map, operator_config = self._build_custom_patterns(custom_patterns, redaction_type)
        entities = list(project.get("entities") or [])

        builtin_results = []
        if entities:
            self._setup_standard_entities(entities, operator_config, redaction_type)
            builtin_results = self.analyzer.analyze(text=text, entities=entities, language=self.language)

        builtin_spans = set()
        for r in builtin_results:
            builtin_spans.update(range(r.start, r.end))

        custom_entity_names = [f"CUSTOM_ENTITY_{i}" for i in range(len(custom_patterns))]
        custom_results = []
        if custom_entity_names:
            async with temp_custom_recognizers(self.analyzer, recognizers):
                for r in self.analyzer.analyze(text=text, entities=custom_entity_names, language=self.language):
                    if not any(i in builtin_spans for i in range(r.start, r.end)):
                        custom_results.append(r)

        results = builtin_results + custom_results
        redacted = self.anonymizer.anonymize(text=text, analyzer_results=results, operators=operator_config)
        findings = [
            {
                "entity_type": custom_entity_map.get(r.entity_type, r.entity_type).strip("[]"),
                "start": r.start,
                "end": r.end,
                "score": round(float(r.score), 4),
            }
            for r in sorted(results, key=lambda r: (r.start, r.end))
        ]
        return TextRedactionResult(redacted_text=redacted.text, findings=findings)

    async def redact_file(self, file_content: BytesIO, file_type: FileType, project_id: str) -> BytesIO:
        logger.info("Redacting file: project=%s type=%s", project_id, file_type.name)

        if file_type == FileType.TEXT:
            text = file_content.read().decode("utf-8")
            redacted = await self.redact_text(text, project_id)
            return BytesIO(redacted.encode("utf-8"))

        if file_type == FileType.IMAGE:
            return await self.redact_image(file_content, project_id)

        if file_type == FileType.PDF:
            return await self.redact_pdf(file_content, project_id)

        if file_type == FileType.JSON:
            data = json.loads(file_content.read().decode("utf-8"))
            redacted = await self.redact_json(data, project_id)
            return BytesIO(json.dumps(redacted, ensure_ascii=False).encode("utf-8"))

        if file_type == FileType.CSV:
            file_content.seek(0)
            df = pd.read_csv(file_content)
            redacted_df = await self.redact_dataframe(df, project_id)
            return BytesIO(redacted_df.to_csv(index=False).encode("utf-8"))

        raise InvalidRedactionTypeError(str(file_type))

    async def redact_image(self, image: BytesIO, project_id: str) -> BytesIO:
        project = await self._get_project(project_id)

        custom_patterns = project.get("customized") or []
        ad_hoc_recognizers = [
            DynamicCustomRecognizer(item["regex"], entity_name=f"CUSTOM_ENTITY_{i}")
            for i, item in enumerate(custom_patterns)
        ]

        entities_to_analyze = list(project.get("entities") or [])
        entities_to_analyze += [f"CUSTOM_ENTITY_{i}" for i in range(len(custom_patterns))]

        pil_image = Image.open(image)
        if pil_image.mode != "RGB":
            pil_image = pil_image.convert("RGB")

        redacted_image = self.image_redactor.redact(
            image=pil_image,
            entities=entities_to_analyze,
            score_threshold=self.score_threshold,
            ad_hoc_recognizers=ad_hoc_recognizers or None,
        )

        output = BytesIO()
        redacted_image.save(output, format="PNG")
        output.seek(0)
        return output

    def _redact_pdf_text_on_page(self, page, page_num, pdf_reader, entities_to_analyze, custom_entity_map):
        text = pdf_reader.pages[page_num].extract_text() or ""
        text = normalize_input_for_presidio(text)
        formatted = []

        if not text.strip():
            return formatted

        results = self.analyzer.analyze(text=text, entities=entities_to_analyze, language=self.language)
        formatted.extend(self._format_results(results, text, custom_entity_map))

        words = page.get_text("words")
        for result in results:
            target = normalize(text[result.start:result.end])
            for i in range(len(words)):
                for j in range(i, len(words)):
                    combined = normalize(" ".join(w[4] for w in words[i:j + 1]))
                    if combined == target:
                        span = words[i:j + 1]
                        rect = fitz.Rect(
                            min(w[0] for w in span),
                            min(w[1] for w in span),
                            max(w[2] for w in span),
                            max(w[3] for w in span),
                        )
                        page.add_redact_annot(rect, fill=(0, 0, 0))
                        break
        page.apply_redactions()
        return formatted

    def _redact_pdf_images_on_page(self, page, pdf_document, entities_to_analyze, ad_hoc_recognizers):
        for img in page.get_images(full=True):
            xref = img[0]
            base_image = pdf_document.extract_image(xref)
            if not base_image:
                continue

            pil_image = Image.open(BytesIO(base_image["image"]))
            if pil_image.mode != "RGB":
                pil_image = pil_image.convert("RGB")

            redacted_image = self.image_redactor.redact(
                image=pil_image,
                entities=entities_to_analyze,
                score_threshold=self.score_threshold,
                ad_hoc_recognizers=ad_hoc_recognizers or None,
            )

            buf = BytesIO()
            redacted_image.save(buf, format="PNG")
            buf.seek(0)
            page.replace_image(xref, stream=buf)

    async def redact_pdf(self, pdf: BytesIO, project_id: str) -> BytesIO:
        project = await self._get_project(project_id)

        custom_patterns = project.get("customized") or []
        ad_hoc_recognizers, custom_entity_map, _operator_config = self._build_custom_patterns(
            custom_patterns, redaction_type="replace"
        )

        entities = list(project.get("entities") or [])
        entities_to_analyze = list(entities)
        entities_to_analyze.extend(f"CUSTOM_ENTITY_{i}" for i in range(len(custom_patterns)))

        pdf.seek(0)
        pdf_document = fitz.open(stream=pdf.getvalue(), filetype="pdf")
        if len(pdf_document) == 0:
            pdf_document.close()
            pdf.seek(0)
            return pdf

        pdf.seek(0)
        with pdfplumber.open(pdf) as pdf_reader:
            async with temp_custom_recognizers(self.analyzer, ad_hoc_recognizers):
                for page_num, page in enumerate(pdf_document):
                    self._redact_pdf_text_on_page(
                        page, page_num, pdf_reader, entities_to_analyze, custom_entity_map
                    )
                    self._redact_pdf_images_on_page(page, pdf_document, entities_to_analyze, ad_hoc_recognizers)

        output = BytesIO()
        pdf_document.save(output, garbage=4, deflate=True, clean=True)
        pdf_document.close()
        output.seek(0)
        return output

    async def redact_json(self, json_data: Any, project_id: str) -> Any:
        project = await self._get_project(project_id)

        async def walk(data: Any) -> Any:
            if isinstance(data, str):
                return await self._redact_text_with_project(data, project)
            if isinstance(data, dict):
                return {k: await walk(v) for k, v in data.items()}
            if isinstance(data, list):
                return [await walk(item) for item in data]
            return data

        return await walk(json_data)

    async def redact_dataframe(self, dataframe: pd.DataFrame, project_id: str) -> pd.DataFrame:
        project = await self._get_project(project_id)
        redacted_df = dataframe.copy()

        new_columns = []
        for col in redacted_df.columns:
            if isinstance(col, str) and col.strip():
                new_columns.append(await self._redact_text_with_project(col, project))
            else:
                new_columns.append(col)
        redacted_df.columns = new_columns

        for col in redacted_df.select_dtypes(include=[object]).columns:
            redacted_col = []
            for val in redacted_df[col]:
                if isinstance(val, str) and val.strip():
                    redacted_col.append(await self._redact_text_with_project(val, project))
                else:
                    redacted_col.append(val)
            redacted_df[col] = redacted_col

        return redacted_df.reset_index(drop=True)

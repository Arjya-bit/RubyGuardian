"""
RubyGuardian Feature Extractor Registry.

Provides a central registry for all feature extractors and a unified
interface for running the full extraction pipeline on Ruby source code.

Usage:
    registry = ExtractorRegistry()
    features = registry.extract_all(ruby_source_code)
"""

import logging
from typing import Any, Protocol

logger = logging.getLogger("rubyguardian.features.extractors")


class FeatureExtractorProtocol(Protocol):
    """Protocol that all feature extractors must implement."""

    name: str
    version: str

    def extract(self, source: str) -> dict[str, Any]:
        ...


class ExtractorRegistry:
    """
    Registry and orchestrator for feature extractors.

    Automatically discovers and registers all built-in extractors.
    Supports adding custom extractors at runtime.
    """

    def __init__(self, auto_register: bool = True):
        self._extractors: dict[str, FeatureExtractorProtocol] = {}
        if auto_register:
            self._register_builtin_extractors()

    def _register_builtin_extractors(self) -> None:
        """Register all built-in feature extractors."""
        from .ast_extractor import ASTFeatureExtractor
        from .entropy_extractor import EntropyFeatureExtractor
        from .behavioral_extractor import BehavioralFeatureExtractor

        for extractor_class in [
            ASTFeatureExtractor,
            EntropyFeatureExtractor,
            BehavioralFeatureExtractor,
        ]:
            instance = extractor_class()
            self.register(instance)

    def register(self, extractor: FeatureExtractorProtocol) -> None:
        """
        Register a feature extractor.

        Args:
            extractor: An object implementing the FeatureExtractorProtocol.

        Raises:
            ValueError: If an extractor with the same name is already registered.
        """
        if extractor.name in self._extractors:
            raise ValueError(
                f"Extractor '{extractor.name}' is already registered. "
                "Use unregister() first to replace it."
            )
        self._extractors[extractor.name] = extractor
        logger.info(
            "Registered extractor '%s' v%s", extractor.name, extractor.version
        )

    def unregister(self, name: str) -> None:
        """Remove a registered extractor by name."""
        if name not in self._extractors:
            raise KeyError(f"No extractor registered with name '{name}'")
        del self._extractors[name]
        logger.info("Unregistered extractor '%s'", name)

    def get(self, name: str) -> FeatureExtractorProtocol:
        """Retrieve a registered extractor by name."""
        if name not in self._extractors:
            raise KeyError(f"No extractor registered with name '{name}'")
        return self._extractors[name]

    @property
    def registered_names(self) -> list[str]:
        """Return sorted list of registered extractor names."""
        return sorted(self._extractors.keys())

    @property
    def count(self) -> int:
        """Return the number of registered extractors."""
        return len(self._extractors)

    def extract_all(self, source: str) -> dict[str, Any]:
        """
        Run all registered extractors and merge their outputs.

        Args:
            source: Ruby source code string.

        Returns:
            Merged dictionary of all extracted features. Keys are prefixed
            with the extractor name if there would be a collision.
        """
        merged: dict[str, Any] = {}
        for name, extractor in sorted(self._extractors.items()):
            try:
                features = extractor.extract(source)
                for key, value in features.items():
                    if key in merged:
                        prefixed_key = f"{name}_{key}"
                        logger.debug(
                            "Feature key collision: '%s' -> '%s'", key, prefixed_key
                        )
                        merged[prefixed_key] = value
                    else:
                        merged[key] = value
            except Exception:
                logger.exception("Extractor '%s' failed on input", name)
                continue

        logger.debug(
            "Extracted %d features from %d extractors",
            len(merged),
            len(self._extractors),
        )
        return merged

    def extract_single(self, extractor_name: str, source: str) -> dict[str, Any]:
        """Run a single named extractor and return its features."""
        extractor = self.get(extractor_name)
        return extractor.extract(source)

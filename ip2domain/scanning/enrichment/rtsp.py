"""Compatibility import for the independent inventory RTSP plugin."""
from ..plugins.base import PluginContext
from ..plugins.rtsp import RTSPPlugin

async def enrich_rtsp(observation,budget):
    plugin=RTSPPlugin()
    if budget.config.web_enrichment and plugin.detect(observation):
        await plugin.discover_endpoints(PluginContext(observation,budget))

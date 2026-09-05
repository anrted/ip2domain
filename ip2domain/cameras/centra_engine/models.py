from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class CentraDiscoveryRequest(BaseModel):
    camera_type: str = Field(default="I", min_length=1, max_length=100)
    base_url: Optional[str] = Field(default=None, max_length=253)
    pin_color: Literal["violet", "blue", "red", "green", "orange", "yellow", "pink", "gray"] = "violet"
    start_id: int = Field(default=1, ge=1, le=1000000)
    end_id: int = Field(default=40000, ge=1, le=1000000)
    entrance_start: int = Field(default=1, ge=1, le=100)
    entrance_end: int = Field(default=5, ge=1, le=100)
    concurrency: int = Field(default=30, ge=1, le=100)
    skip_existing: bool = False


class CentraCoordinatesRequest(BaseModel):
    address: str = Field(min_length=1, max_length=500)
    coordinates: List[float] = Field(min_items=2, max_items=2)


class CentraPersonDetectionRequest(BaseModel):
    camera_ids: List[str] = Field(default_factory=list, max_items=100)
    all_cameras: bool = False
    camera_type: str = Field(default="", max_length=1)
    confidence: float = Field(default=0.45, ge=0.2, le=0.9)


class CentraGeocodeRequest(BaseModel):
    address: str = Field(min_length=1, max_length=500)

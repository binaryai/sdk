# Generated by ariadne-codegen
# Source: ./src/binaryai/query.graphql

from typing import Any, List, Optional

from pydantic import Field

from .base_model import BaseModel


class FunctionsInfo(BaseModel):
    file: Optional["FunctionsInfoFile"]


class FunctionsInfoFile(BaseModel):
    decompile_result: Optional["FunctionsInfoFileDecompileResult"] = Field(
        alias="decompileResult"
    )


class FunctionsInfoFileDecompileResult(BaseModel):
    functions: Optional[List["FunctionsInfoFileDecompileResultFunctions"]]


class FunctionsInfoFileDecompileResultFunctions(BaseModel):
    offset: Any
    name: str
    embedding: Optional["FunctionsInfoFileDecompileResultFunctionsEmbedding"] = None
    pseudo_code: Optional["FunctionsInfoFileDecompileResultFunctionsPseudoCode"] = (
        Field(alias="pseudoCode")
    )


class FunctionsInfoFileDecompileResultFunctionsEmbedding(BaseModel):
    vector: List[float]
    version: str


class FunctionsInfoFileDecompileResultFunctionsPseudoCode(BaseModel):
    code: str


FunctionsInfo.model_rebuild()
FunctionsInfoFile.model_rebuild()
FunctionsInfoFileDecompileResult.model_rebuild()
FunctionsInfoFileDecompileResultFunctions.model_rebuild()

"""
Patcher strategies package.
Provides implementations for S1 (Conservative), S2 (Moderate), and S3 (Aggressive) patching.
"""
from .s1 import patch_s1, TRANSFORM_RULES as S1_RULES
from .s2 import patch_s2, TRANSFORM_RULES as S2_RULES
from .s3 import patch_s3, TRANSFORM_RULES as S3_RULES

__all__ = ["patch_s1", "patch_s2", "patch_s3", "S1_RULES", "S2_RULES", "S3_RULES"]

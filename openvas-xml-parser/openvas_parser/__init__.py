"""
OpenVAS XML Parser Package

Convert OpenVAS XML reports to structured JSON format.
"""

from .parser import convert_openvas_xml_to_json, _parse_tags

__version__ = "1.0.0"
__author__ = "Advanced Vulnerability Management System"
__all__ = ["convert_openvas_xml_to_json", "_parse_tags"]

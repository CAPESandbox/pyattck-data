import re
from typing import Any
from pydantic import TypeAdapter


# https://ihateregex.io/expr/semver/

PATTERNS = {
    'semversion': {
        'pattern': r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
        'examples': ['1.1.1', '0.1.2', '99.99.99']
    },
    'types': {
        'pattern': None,
        'examples': ['relationship', 'x-mitre-matrix', 'identity', 'marking-definition', 'course-of-action', 'malware', 'tool', 'intrusion-set', 'x-mitre-data-source', 'x-mitre-data-component', 'x-mitre-tactic', 'attack-pattern', 'bundle']
    },
    'reference': {
        'pattern': None,
        'examples': ['identity', 'marking-definition', 'course-of-action', 'malware', 'tool', 'intrusion-set', 'x-mitre-data-source', 'x-mitre-data-component', 'x-mitre-tactic', 'attack-pattern']
    },
    'domains': {
        'pattern': None,
        'examples': ['mobile-attack', 'enterprise-attack']
    },
    'platforms': {
        'pattern': None,
        'examples': ['Windows', 'Android', 'iOS', 'macOS', 'Azure AD', 'SaaS', 'Network', 'Google Workspace', 'PRE', 'Containers', 'IaaS', 'Linux', 'Office 365']
    },
    'relationship': {
        'pattern': None,
        'examples': ['revoked-by', 'subtechnique-of', 'uses', 'detects', 'mitigates','related-to']
    }
}


REGEXS = {
    'semversion': re.compile(PATTERNS['semversion']['pattern'])
}


def validate_semversion(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError('string required')
    m = REGEXS['semversion'].fullmatch(v.upper())
    if not m:
        raise ValueError('Invalid SemVersion format')
    return f'{m.group(1)} {m.group(2)}'

def validate_id(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError('string required')
    if '--' in v:
        type_str, id_str = v.split('--')
    else:
        type_str = v
    if type_str not in PATTERNS['types']['examples']:
        raise ValueError('Invalid Id attribute.')
    return v

def validate_domain(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError('string required')
    if v not in PATTERNS['domains']['examples']:
        raise ValueError('Invalid MitreDomain attribute.')
    return v

def validate_platform(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError('string required')
    if v not in PATTERNS['platforms']['examples']:
        raise ValueError('Invalid MitrePlatform attribute.')
    return v

def validate_relationship(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError('string required')
    if v not in PATTERNS['relationship']['examples']:
        raise ValueError('Invalid MitreRelationship attribute.')
    return v

class SemVersion(str):
    def __new__(cls, v=None):
        if v is None:
            return super().__new__(cls)
        return super().__new__(cls, validate_semversion(v))
    def __repr__(self):
        return f'SemVersion({super().__repr__()})'
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_after_validator_function(validate_semversion, core_schema.str_schema())

class Id(str):
    def __new__(cls, v=None):
        if v is None:
            return super().__new__(cls)
        return super().__new__(cls, validate_id(v))
    def __repr__(self):
        return f'Id({super().__repr__()})'
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_after_validator_function(validate_id, core_schema.str_schema())

class MitreDomain(str):
    def __new__(cls, v=None):
        if v is None:
            return super().__new__(cls)
        return super().__new__(cls, validate_domain(v))
    def __repr__(self):
        return f'MitreDomain({super().__repr__()})'
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_after_validator_function(validate_domain, core_schema.str_schema())

class MitrePlatform(str):
    def __new__(cls, v=None):
        if v is None:
            return super().__new__(cls)
        return super().__new__(cls, validate_platform(v))
    def __repr__(self):
        return f'MitrePlatform({super().__repr__()})'
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_after_validator_function(validate_platform, core_schema.str_schema())

class MitreRelationship(str):
    def __new__(cls, v=None):
        if v is None:
            return super().__new__(cls)
        return super().__new__(cls, validate_relationship(v))
    def __repr__(self):
        return f'MitreRelationship({super().__repr__()})'
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_after_validator_function(validate_relationship, core_schema.str_schema())

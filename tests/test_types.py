# -*- coding: utf-8 -*-
import pytest


from pyattck_data.types import (
    Id,
    MitreDomain,
    MitrePlatform,
    PATTERNS,
    SemVersion
)


from pydantic import TypeAdapter

def test_id_type():
    ta = TypeAdapter(Id)
    for example in PATTERNS["types"]["examples"]:
        assert ta.validate_python(example)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('asdefasdf')
    assert "Invalid Id attribute" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('asdefasdf-')
    assert "Invalid Id attribute" in str(excinfo.value)


def test_semversion_type():
    ta = TypeAdapter(SemVersion)
    for example in PATTERNS["semversion"]["examples"]:
        assert ta.validate_python(example)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('asdefasdf')
    assert "Invalid SemVersion format" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('0000')
    assert "Invalid SemVersion format" in str(excinfo.value)


def test_mitre_domain_type():
    ta = TypeAdapter(MitreDomain)
    for example in PATTERNS["domains"]["examples"]:
        assert ta.validate_python(example)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('asdefasdf')
    assert "Invalid MitreDomain attribute" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('0000')
    assert "Invalid MitreDomain attribute" in str(excinfo.value)


def test_mitre_platform_type():
    ta = TypeAdapter(MitrePlatform)
    for example in PATTERNS["platforms"]["examples"]:
        assert ta.validate_python(example)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('android')
    assert "Invalid MitrePlatform attribute" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        ta.validate_python('relationship')
    assert "Invalid MitrePlatform attribute" in str(excinfo.value)

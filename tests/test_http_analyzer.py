from ip2domain.modules.http_analyzer import HTTPTechAnalyzer


def test_http_tech_analyzer():
    analyzer = HTTPTechAnalyzer(timeout=5)
    # Test grade calculation
    assert analyzer._calculate_grade(7, 7) == "A+"
    assert analyzer._calculate_grade(0, 7) == "F"
    assert analyzer._calculate_grade(4, 7) == "B"

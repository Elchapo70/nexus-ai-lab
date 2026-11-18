from app.github_scanner import python_findings, production_candidate

def test_python_ast_ignores_strings_and_comments():
    source = 'message = "eval(user_input)"\n# DEBUG = True\n'
    assert python_findings(source, "app/example.py") == []

def test_python_ast_detects_real_calls():
    source = 'DEBUG = True\nresult = eval(user_input)\n'
    findings = python_findings(source, "app/main.py")
    assert {f["rule"] for f in findings} == {"EVAL", "DEBUG_TRUE"}

def test_production_filter():
    assert production_candidate("app/main.py")
    assert not production_candidate("examples/demo.py")
    assert not production_candidate("tests/test_main.py")
    assert not production_candidate("docs/example.py")

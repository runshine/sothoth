import re
from pathlib import Path


APP_JS = Path(__file__).resolve().parents[1] / "dashboard" / "static" / "app.js"


def test_dashboard_dynamic_click_args_use_data_attributes():
    source = APP_JS.read_text(encoding="utf-8")

    assert "this.js(" not in source
    assert 'data-run="${this.attr(r.name)}"' in source
    assert 'onclick="App.selectRun(this.dataset.run, event)"' in source

    unsafe_patterns = [
        r'onclick="App\.[^"\n]*\$\{this\.',
        r'onclick="event\.stopPropagation\(\); App\.[^"\n]*\$\{this\.',
    ]
    for pattern in unsafe_patterns:
        assert not re.search(pattern, source)


def test_dashboard_attr_helper_escapes_html_attribute_quotes():
    source = APP_JS.read_text(encoding="utf-8")

    assert "attr(s)" in source
    assert ".replace(/\"/g, '&quot;')" in source
    assert ".replace(/'/g, '&#39;')" in source

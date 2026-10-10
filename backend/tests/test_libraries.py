"""Library recognition from page markup. No network."""

from sentinelforge.engine.libraries import inspect_html, is_affected, same_host_script, version_from_banner


def ids_and_versions(html: str):
    return [(hit.rule.case_id, hit.version) for hit in inspect_html(html)]


def test_versions_in_urls_are_recognized_and_body_text_is_not():
    html = """
    <html><head>
      <script src="https://cdn.example/jquery-1.12.4.min.js"></script>
      <script src="https://cdn.example/npm/jquery@3.7.1/dist/jquery.min.js"></script>
      <script src="https://cdn.example/ui/1.12.1/jquery-ui.min.js"></script>
      <script src="https://cdn.example/npm/lodash@4.17.20/lodash.min.js"></script>
      <link rel="stylesheet" href="https://cdn.example/bootstrap-3.4.0.min.css">
      <script src="https://cdn.example/moment.js/2.29.4/moment.min.js"></script>
      <script src="https://cdn.example/angularjs/1.6.4/angular.min.js"></script>
      <script src="/js/jquery.min.js?ver=2.2.4"></script>
      <link rel="stylesheet" href="/bootstrap-icons.min.css">
      <script src="https://cdn.example/npm/@angular/core@16.2.0/fesm.js"></script>
    </head>
    <body><p>The docs mention jquery-1.8.0.min.js and lodash@1.0.0 as examples.</p></body>
    </html>
    """
    found = ids_and_versions(html)
    assert ("WEB-031", (1, 12, 4)) in found
    assert ("WEB-031", (3, 7, 1)) in found
    assert ("WEB-031", (2, 2, 4)) in found
    assert ("WEB-032", (1, 12, 1)) in found
    assert ("WEB-034", (4, 17, 20)) in found
    assert ("WEB-033", (3, 4, 0)) in found
    assert ("WEB-035", (2, 29, 4)) in found
    assert ("WEB-036", (1, 6, 4)) in found
    assert all(item[0] != "WEB-036" or item[1][0] == 1 for item in found)
    assert not any(version == (16, 2, 0) for _, version in found)
    assert not any(version == (1, 8, 0) for _, version in found)
    assert not any(version == (1, 0, 0) for _, version in found)


def test_comments_are_not_libraries():
    html = "<!-- <script src='jquery-1.8.0.min.js'></script> --><script src='jquery-3.7.1.min.js'></script>"
    assert ids_and_versions(html) == [("WEB-031", (3, 7, 1))]


def test_fix_versions_are_not_flagged_and_older_ones_are():
    jquery = next(hit.rule for hit in inspect_html("<script src='jquery-3.5.0.min.js'></script>"))
    assert is_affected(jquery, (3, 4, 1))
    assert not is_affected(jquery, (3, 5, 0))
    bootstrap = next(hit.rule for hit in inspect_html("<link rel='stylesheet' href='bootstrap-4.3.0.min.css'>"))
    assert is_affected(bootstrap, (3, 4, 0))
    assert not is_affected(bootstrap, (3, 4, 1))
    assert is_affected(bootstrap, (4, 3, 0))
    assert not is_affected(bootstrap, (4, 3, 1))
    assert not is_affected(bootstrap, (5, 3, 3))
    lodash = next(hit.rule for hit in inspect_html("<script src='lodash@4.17.23/lodash.min.js'></script>"))
    assert is_affected(lodash, (4, 17, 23))
    assert not is_affected(lodash, (4, 18, 0))
    angular = next(hit.rule for hit in inspect_html("<script src='angularjs/1.8.3/angular.min.js'></script>"))
    assert is_affected(angular, (1, 8, 3))
    assert not is_affected(angular, (4, 0, 0))


def test_same_host_scripts_stay_on_the_scanned_host():
    page = "http://127.0.0.1:9/app/"
    assert same_host_script("/js/jquery.min.js", page, "127.0.0.1") == "http://127.0.0.1:9/js/jquery.min.js"
    assert same_host_script("https://cdn.invalid/jquery.min.js", page, "127.0.0.1") is None
    assert same_host_script("javascript:alert(1)", page, "127.0.0.1") is None


def test_version_banner_is_read_from_the_start_of_a_script():
    jquery = next(hit.rule for hit in inspect_html("<script src='jquery.min.js'></script>"))
    assert version_from_banner(jquery, "/*! jQuery v1.11.0 | (c) jQuery Foundation */") == (1, 11, 0)
    moment = next(hit.rule for hit in inspect_html("<script src='moment.min.js'></script>"))
    assert version_from_banner(moment, "//! moment.js\n//! version : 2.24.0\n") == (2, 24, 0)
    assert version_from_banner(moment, "version : 2.24.0") is None

"""The source viewer and import review consume the same immutable uploaded bytes and shared analysis."""
import hashlib
import json


def check_source_analysis(browser, upload):
    invalid = b"# synthetic\r\ncounter\x00accept\r\n"
    upload("Analysis failure snapshot", invalid)
    source_id = browser.location.split("sourceId=")[1]
    assert browser.request("/manage/sources/download?sourceId=" + source_id, 200).encode() == invalid
    report = json.loads(browser.request("/manage/sources/review?sourceId=" + source_id, 200))
    assert report["sourceSha256"] == hashlib.sha256(invalid).hexdigest()
    assert report["review"]["inventoryComplete"] is False
    assert report["review"]["diagnostic"] == "source.invalidCharacter"
    assert report["review"]["signals"] == [] and report["review"]["canConvert"] is False
    assert report["schemaVersion"] == 2 and report["structure"]["isComplete"] is False
    assert report["structure"]["diagnostic"]["span"]["line"] == 2
    html = browser.request("/manage/sources?sourceId=" + source_id, 200)
    assert "Inventory incomplete" in html and "source.invalidCharacter" in html and "Conversion blocked" in html

    continued = b'ether \\\r\n saddr 02:00:00:00:00:01 accept\rcounter\n$log @notrack "jump"\n'
    upload("Shared physical source positions", continued)
    source_id = browser.location.split("sourceId=")[1]
    assert browser.request("/manage/sources/download?sourceId=" + source_id, 200).encode() == continued
    report = json.loads(browser.request("/manage/sources/review?sourceId=" + source_id, 200))
    assert report["sourceSha256"] == hashlib.sha256(continued).hexdigest()
    signals = {s["code"]: s["lines"] for s in report["review"]["signals"]}
    assert signals == {"review.sourceMac": [1], "gap.counters": [3], "source.unclassifiedStatements": [1, 3, 4]}
    assert report["review"]["inventoryComplete"] is True and report["review"]["canConvert"] is False
    assert report["structure"]["isComplete"] is True and report["structure"]["groupCount"] == 0
    html = browser.request("/manage/sources?sourceId=" + source_id, 200)
    assert "Inventory incomplete" not in html and "review.sourceMac" in html and "gap.counters" in html
    assert "Conversion blocked" in html
    contextual = b'define hidden = table inet fake { chain hidden {} }\nfuture_private statement\ntable inet sample { set raw { chain hidden {} } chain input { counter accept; } }\n'
    upload("Contextual declaration accounting", contextual)
    source_id = browser.location.split("sourceId=")[1]
    report = json.loads(browser.request("/manage/sources/review?sourceId=" + source_id, 200))
    assert report["schemaVersion"] == 2 and report["sourceSha256"] == hashlib.sha256(contextual).hexdigest()
    assert report["review"]["tableDeclarations"] == report["review"]["chainDeclarations"] == 1
    signal = next(s for s in report["review"]["signals"] if s["code"] == "source.unclassifiedStatements")
    assert signal["lines"] == [2] and not report["review"]["canConvert"]
    assert "future_private" not in json.dumps(report) and "hidden" not in json.dumps(report)
    html = browser.request("/manage/sources?sourceId=" + source_id, 200)
    assert "source.unclassifiedStatements" in html and "Conversion blocked" in html
    assert browser.request("/manage/sources/download?sourceId=" + source_id, 200).encode() == contextual
    mismatched = b'# synthetic\r\ntable inet sample {\r\n counter ]\r\n'
    upload("Mismatched source group", mismatched)
    source_id = browser.location.split("sourceId=")[1]
    report = json.loads(browser.request("/manage/sources/review?sourceId=" + source_id, 200))
    summary = report["structure"]
    assert report["schemaVersion"] == 2 and report["sourceSha256"] == hashlib.sha256(mismatched).hexdigest()
    assert not summary["isComplete"] and summary["tokenCount"] == summary["groupCount"] == summary["maximumDepth"] == 0
    assert summary["diagnostic"]["code"] == "source.mismatchedDelimiter"
    assert summary["diagnostic"]["span"]["line"] == 3 and summary["diagnostic"]["span"]["column"] == 10
    assert report["review"]["signals"] == [] and not report["review"]["canConvert"]
    assert "sample" not in json.dumps(report) and "counter" not in json.dumps(report)
    html = browser.request("/manage/sources?sourceId=" + source_id, 200)
    assert "Check line 3, column 10" in html and "Source structure is incomplete" in html
    assert "Review topics are unavailable" in html and "No catalogued keywords were found" not in html
    assert browser.request("/manage/sources/download?sourceId=" + source_id, 200).encode() == mismatched
    print("PASS: shared structured viewer/import analysis, schema-2 diagnostics, exact originals, physical source positions and no partial tree/inventory")

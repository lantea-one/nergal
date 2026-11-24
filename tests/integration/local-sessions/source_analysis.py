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
    html = browser.request("/manage/sources?sourceId=" + source_id, 200)
    assert "Inventory incomplete" in html and "source.invalidCharacter" in html and "Conversion blocked" in html

    continued = b'ether \\\r\n saddr 02:00:00:00:00:01 accept\rcounter\n$log @notrack "jump"\n'
    upload("Shared physical source positions", continued)
    source_id = browser.location.split("sourceId=")[1]
    assert browser.request("/manage/sources/download?sourceId=" + source_id, 200).encode() == continued
    report = json.loads(browser.request("/manage/sources/review?sourceId=" + source_id, 200))
    assert report["sourceSha256"] == hashlib.sha256(continued).hexdigest()
    signals = {s["code"]: s["lines"] for s in report["review"]["signals"]}
    assert signals == {"review.sourceMac": [1], "gap.counters": [3]}
    assert report["review"]["inventoryComplete"] is True and report["review"]["canConvert"] is False
    html = browser.request("/manage/sources?sourceId=" + source_id, 200)
    assert "Inventory incomplete" not in html and "review.sourceMac" in html and "gap.counters" in html
    assert "Conversion blocked" in html
    print("PASS: shared source viewer/import analysis, exact failed/continued originals, physical source positions and no partial inventory")

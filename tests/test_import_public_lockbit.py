from analysis.import_public_lockbit import classify_signal


def test_classify_signal_detects_ransom_note() -> None:
    event = {
        "event_id": "11",
        "TargetFilename": r"C:\Temp\Downloads\ransom.html",
        "Image": r"C:\Program Files\7-Zip\7zG.exe",
    }

    signal = classify_signal(event)

    assert signal is not None
    assert signal[0] == "ransom_note"
    assert signal[1] == 100611


def test_classify_signal_detects_shadow_delete() -> None:
    event = {
        "event_id": "12",
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Shadow\Example",
        "Image": r"C:\Windows\system32\svchost.exe",
    }

    signal = classify_signal(event)

    assert signal is not None
    assert signal[0] == "shadow_delete"
    assert signal[1] == 100610
